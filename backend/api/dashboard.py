from typing import Optional
from fastapi import APIRouter,Depends,Query
from backend.core.database import connection
from backend.core.security import current_user
from backend.core.util import now
router=APIRouter(prefix='/api',tags=['dashboard and risk'])
@router.get('/dashboard')
def dashboard(entity:Optional[str]=None,user=Depends(current_user)):
    with connection() as c:
        filt=' WHERE kind=?' if entity else '';args=(entity,) if entity else ()
        assets=c.execute(f'SELECT count(*) total,AVG(compliance) compliance FROM assets{filt}',args).fetchone()
        sev=c.execute("SELECT f.severity,count(*) n FROM findings f JOIN assets a ON a.id=f.asset_id WHERE f.state IN ('Open','In Progress')"+(' AND a.kind=?' if entity else '')+' GROUP BY f.severity',args).fetchall()
        web=c.execute("SELECT count(*) total,sum(CASE WHEN waf='Protected' THEN 1 ELSE 0 END) protected FROM assets WHERE kind='Website'").fetchone()
        noncomp=c.execute('SELECT count(*) FROM assets WHERE compliance IS NOT NULL AND compliance<80'+(' AND kind=?' if entity else ''),(entity,) if entity else ()).fetchone()[0]
        web_count=0 if entity=='Server' else c.execute("SELECT count(*) FROM assets WHERE kind='Website'").fetchone()[0]
        server_count=0 if entity=='Website' else c.execute("SELECT count(*) FROM assets WHERE kind='Server'").fetchone()[0]
        return {'assets':assets['total'],'websites':web_count,'servers':server_count, 'openFindings':sum(x['n'] for x in sev),'bySeverity':{x['severity']:x['n'] for x in sev},'compliancePercent':round(assets['compliance'] or 0,1),'nonCompliantAssets':noncomp,'websitesWafProtected':web['protected'] or 0,'websitesTotal':web['total'],'generatedAt':now()}
@router.get('/risk/priorities')
def priorities(entity:Optional[str]=None,limit:int=Query(100,ge=1,le=500),user=Depends(current_user)):
    with connection() as c:
        rows=c.execute("SELECT f.*,a.name asset_name,a.kind asset_kind,a.criticality,a.classification,a.compliance FROM findings f JOIN assets a ON a.id=f.asset_id WHERE f.state IN ('Open','In Progress')"+(' AND a.kind=?' if entity else ''),((entity,) if entity else ())).fetchall()
    weights={'Critical':40,'High':25,'Medium':12,'Low':5,'Informational':1};items=[]
    from datetime import datetime,timezone
    def age_points(value):
        if not value:return 0
        try:
            seen=datetime.fromisoformat(value.replace('Z','+00:00'))
            if seen.tzinfo is None:seen=seen.replace(tzinfo=timezone.utc)
            return max(0,min(15,(datetime.now(timezone.utc)-seen).days//7))
        except (ValueError,TypeError):return 0
    for r in rows:
        d=dict(r);ev={}
        try:ev=__import__('json').loads(d['evidence'] or '{}')
        except Exception:pass
        score=weights.get(d['severity'],0)+(20 if d['classification']=='External facing' else 0)+(15 if d['criticality']=='Critical' else 0)+(10 if ev.get('kev') else 0)+int(float(ev.get('epss') or 0)*10)+age_points(d['first_seen'] or d['created_at'])
        items.append({**d,'riskScore':min(score,100),'riskFactors':{'severity':d['severity'],'externalFacing':d['classification']=='External facing','criticalAsset':d['criticality']=='Critical','kev':bool(ev.get('kev')),'epss':ev.get('epss')}})
    return {'items':sorted(items,key=lambda x:(-x['riskScore'],x['due_at'] or '9999',x['id']))[:limit],'sortRule':'riskScore desc, due date asc, finding ID asc','scoreModel':'Transparent heuristic; not a calibrated probability'}
