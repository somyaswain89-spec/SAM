from typing import Optional
from fastapi import APIRouter,Depends,HTTPException,Query
from backend.core.database import connection
from backend.core.security import current_user,require_roles
from backend.core.util import now,dump,audit
from backend.schemas.common import ExceptionCreate,ReviewDecision,ContainmentRequest,WorkflowCreate
from datetime import datetime,timezone
import uuid,json
router=APIRouter(prefix='/api',tags=['governance and response'])
@router.post('/exceptions',status_code=201)
def request_exception(body:ExceptionCreate,user=Depends(require_roles('admin','security_admin','analyst'))):
    try:expiry=datetime.fromisoformat(body.expires_at.replace('Z','+00:00'))
    except ValueError:raise HTTPException(422,'expires_at must be ISO-8601')
    if expiry<=datetime.now(timezone.utc):raise HTTPException(422,'Expiry must be in the future')
    eid='EX-'+uuid.uuid4().hex[:10].upper();t=now()
    with connection() as c:
        if not c.execute('SELECT 1 FROM assets WHERE id=?',(body.asset_id,)).fetchone():raise HTTPException(404,'Asset not found')
        if body.finding_id and not c.execute('SELECT 1 FROM findings WHERE id=? AND asset_id=?',(body.finding_id,body.asset_id)).fetchone():raise HTTPException(422,'Finding does not belong to asset')
        c.execute('INSERT INTO exception_requests(id,asset_id,finding_id,requested_by,reason,expires_at,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?, ?,?)',(eid,body.asset_id,body.finding_id,user['id'],body.reason,expiry.isoformat(),'Pending',t,t));audit(c,user,'exception.request','exception',eid,body.model_dump())
        return dump(c.execute('SELECT * FROM exception_requests WHERE id=?',(eid,)).fetchone())
@router.get('/exceptions')
def list_exceptions(state:Optional[str]=None,user=Depends(current_user)):
    with connection() as c:rows=c.execute('SELECT e.*,a.name asset_name FROM exception_requests e JOIN assets a ON a.id=e.asset_id'+(' WHERE e.status=?' if state else '')+' ORDER BY e.created_at DESC',(state,) if state else ()).fetchall()
    return {'items':[dump(x) for x in rows]}
@router.post('/exceptions/{eid}/review')
def review_exception(eid:str,body:ReviewDecision,user=Depends(require_roles('admin','security_admin'))):
    with connection() as c:
        r=c.execute("SELECT * FROM exception_requests WHERE id=? AND status='Pending'",(eid,)).fetchone()
        if not r:raise HTTPException(404,'Pending exception not found')
        if r['requested_by']==user['id']:raise HTTPException(409,'Requester cannot approve their own exception')
        st='Approved' if body.decision=='Approve' else 'Rejected';c.execute('UPDATE exception_requests SET status=?,reviewed_by=?,review_note=?,updated_at=? WHERE id=?',(st,user['id'],body.note,now(),eid));audit(c,user,'exception.'+st.lower(),'exception',eid,{'note':body.note});return dump(c.execute('SELECT * FROM exception_requests WHERE id=?',(eid,)).fetchone())
@router.post('/workflows',status_code=201)
def create_workflow(body:WorkflowCreate,user=Depends(current_user)):
    wid='WF-'+uuid.uuid4().hex[:10].upper();t=now()
    with connection() as c:
        if body.asset_id and not c.execute('SELECT 1 FROM assets WHERE id=?',(body.asset_id,)).fetchone():raise HTTPException(404,'Asset not found')
        if body.finding_id and not c.execute('SELECT 1 FROM findings WHERE id=?',(body.finding_id,)).fetchone():raise HTTPException(404,'Finding not found')
        c.execute('INSERT INTO workflow_requests(id,kind,asset_id,finding_id,status,payload,requested_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)',(wid,body.kind,body.asset_id,body.finding_id,'Pending',json.dumps(body.payload),user['id'],t,t));audit(c,user,'workflow.create','workflow',wid,body.model_dump());return dump(c.execute('SELECT * FROM workflow_requests WHERE id=?',(wid,)).fetchone())
@router.get('/workflows')
def list_workflows(user=Depends(current_user)):
    with connection() as c:rows=c.execute('SELECT * FROM workflow_requests ORDER BY created_at DESC LIMIT 500').fetchall()
    return {'items':[dump(x) for x in rows]}
@router.post('/containment/requests',status_code=202)
def containment(body:ContainmentRequest,user=Depends(require_roles('admin','security_admin'))):
    if not body.acknowledge_impact:raise HTTPException(409,'Business impact must be acknowledged before requesting containment')
    aid='CT-'+uuid.uuid4().hex[:10].upper();t=now()
    with connection() as c:
        a=c.execute('SELECT * FROM assets WHERE id=?',(body.asset_id,)).fetchone()
        if not a:raise HTTPException(404,'Asset not found')
        impact=f"{a['criticality']} criticality {a['kind']} owned by {a['owner'] or 'Unknown owner'}; status {a['status']}; {a['compliance']}% compliance. Review service dependencies and recovery plan."
        c.execute('INSERT INTO containment_actions(id,asset_id,action,status,impact,requested_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',(aid,body.asset_id,body.action,'Approval required',impact,user['id'],t,t));audit(c,user,'containment.request','containment',aid,{'asset_id':body.asset_id,'action':body.action,'impact':impact})
        return {'id':aid,'assetId':body.asset_id,'action':body.action,'status':'Approval required','impact':impact,'executionEnabled':False}
@router.get('/containment/requests')
def list_containment(user=Depends(current_user)):
    with connection() as c:rows=c.execute('SELECT * FROM containment_actions ORDER BY created_at DESC').fetchall()
    return {'items':[dump(x) for x in rows],'executionEnabled':False}
@router.post('/containment/requests/{action_id}/decision')
def decide_containment(action_id:str,body:ReviewDecision,user=Depends(require_roles('admin','security_admin'))):
    with connection() as c:
        action=c.execute("SELECT * FROM containment_actions WHERE id=? AND status='Approval required'",(action_id,)).fetchone()
        if not action:raise HTTPException(404,'Pending containment request not found')
        if action['requested_by']==user['id']:raise HTTPException(409,'Requester cannot approve their own containment request')
        state='Approved · simulated' if body.decision=='Approve' else 'Rejected'
        c.execute('UPDATE containment_actions SET status=?,approved_by=?,updated_at=? WHERE id=?',(state,user['id'],now(),action_id))
        if body.decision=='Approve':
            target='Quarantined' if action['action']=='Quarantine' else 'Active'
            c.execute('UPDATE assets SET status=?,updated_at=? WHERE id=?',(target,now(),action['asset_id']))
        audit(c,user,'containment.'+body.decision.lower(),'containment',action_id,{'note':body.note,'executionEnabled':False})
        return {'id':action_id,'status':state,'assetStatusChanged':body.decision=='Approve','externalActionExecuted':False,'note':'Only SAM QA state changed; no endpoint, network, cloud, WAF, or server operation was sent.'}
