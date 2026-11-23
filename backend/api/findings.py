from typing import Optional
from fastapi import APIRouter,Depends,HTTPException,Query
from backend.core.database import connection
from backend.core.security import current_user,require_roles
from backend.core.util import now,dump,audit
from backend.schemas.common import FindingCreate
router=APIRouter(prefix='/api/findings',tags=['vulnerability management'])
@router.get('')
def list_findings(severity:Optional[str]=None,state:Optional[str]=None,asset_id:Optional[str]=None,sort:str='risk',direction:str='desc',limit:int=Query(100,ge=1,le=500),offset:int=Query(0,ge=0),user=Depends(current_user)):
    orders={'risk':"CASE f.severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 1 ELSE 0 END",'first_seen':'f.first_seen','due_at':'f.due_at','updated_at':'f.updated_at'}
    if sort not in orders or direction not in ('asc','desc'):raise HTTPException(422,'Unsupported sort')
    clauses=[];args=[]
    for col,val in [('severity',severity),('state',state),('asset_id',asset_id)]:
        if val:clauses.append('f.'+col+'=?');args.append(val)
    where=' WHERE '+' AND '.join(clauses) if clauses else ''
    with connection() as c:
        total=c.execute('SELECT count(*) FROM findings f'+where,args).fetchone()[0]
        rows=c.execute(f"SELECT f.*,a.name asset_name,a.kind asset_kind,a.criticality asset_criticality,a.classification FROM findings f JOIN assets a ON a.id=f.asset_id{where} ORDER BY {orders[sort]} {direction.upper()}, f.updated_at DESC, f.id LIMIT ? OFFSET ?",(*args,limit,offset)).fetchall()
    return {'items':[dump(x) for x in rows],'total':total,'sort':sort,'direction':direction,'limit':limit,'offset':offset}
@router.post('',status_code=201)
def upsert_finding(body:FindingCreate,user=Depends(require_roles('admin','security_admin','analyst'))):
    import json
    t=now();d=body.model_dump()
    with connection() as c:
        if not c.execute('SELECT 1 FROM assets WHERE id=?',(body.asset_id,)).fetchone():raise HTTPException(422,'Asset does not exist')
        # Stable source IDs make repeated imports update one finding instead of creating duplicates.
        existing=c.execute('SELECT id FROM findings WHERE source=? AND source_finding_id=? AND asset_id=?',(d['source'],d['source_finding_id'],d['asset_id'])).fetchone() if d['source_finding_id'] else None
        finding_id=existing['id'] if existing else d['id']
        c.execute('INSERT INTO findings(id,asset_id,source,source_finding_id,title,cve,severity,state,first_seen,last_seen,due_at,evidence,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET asset_id=excluded.asset_id,title=excluded.title,cve=excluded.cve,severity=excluded.severity,state=excluded.state,last_seen=excluded.last_seen,due_at=excluded.due_at,evidence=excluded.evidence,updated_at=excluded.updated_at',(finding_id,d['asset_id'],d['source'],d['source_finding_id'],d['title'],d['cve'],d['severity'],d['state'],d['first_seen'],d['last_seen'],d['due_at'],json.dumps({**d['evidence'],'cvss':d['cvss'],'epss':d['epss'],'kev':d['kev']}),t,t))
        audit(c,user,'finding.upsert','finding',finding_id,{'asset_id':body.asset_id,'state':body.state,'source':body.source})
        return dump(c.execute('SELECT * FROM findings WHERE id=?',(finding_id,)).fetchone())
@router.patch('/{finding_id}/state')
def set_state(finding_id:str,state:str,user=Depends(require_roles('admin','security_admin','analyst'))):
    if state not in ('Open','In Progress','Resolved','Accepted Risk'):raise HTTPException(422,'Invalid state')
    with connection() as c:
        if not c.execute('SELECT 1 FROM findings WHERE id=?',(finding_id,)).fetchone():raise HTTPException(404,'Finding not found')
        c.execute('UPDATE findings SET state=?,updated_at=? WHERE id=?',(state,now(),finding_id));audit(c,user,'finding.state','finding',finding_id,{'state':state})
        return dump(c.execute('SELECT * FROM findings WHERE id=?',(finding_id,)).fetchone())
