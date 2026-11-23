from typing import Optional
from fastapi import APIRouter,Depends
from pydantic import BaseModel,Field
from backend.core.security import current_user
from backend.core.database import connection
from backend.core.util import now
router=APIRouter(prefix='/api/analyst',tags=['AI security analyst'])
class Question(BaseModel): question:str=Field(min_length=1,max_length=1000); entity:Optional[str]=None
@router.post('/ask')
def ask(body:Question,user=Depends(current_user)):
    q=body.question.lower(); filt=' AND kind=?' if body.entity else '';args=(body.entity,) if body.entity else ()
    with connection() as c:
        assets=c.execute('SELECT id,name,kind,classification,owner,criticality,compliance,waf FROM assets WHERE status!=\'Retired\''+filt,args).fetchall()
        findings=c.execute("SELECT f.id,f.title,f.severity,f.cve,f.asset_id,a.name asset_name,a.classification FROM findings f JOIN assets a ON a.id=f.asset_id WHERE f.state IN ('Open','In Progress')"+(' AND a.kind=?' if body.entity else '')+" ORDER BY CASE f.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END LIMIT 100",args).fetchall()
    if any(k in q for k in ('rescan','scan again')):answer='To request a rescan, create a Rescan workflow with the asset, finding, reason, and approved time window. A real scan requires a configured scanner connector and explicit approval.'
    elif any(k in q for k in ('quarantine','isolate','contain')):answer='Use the containment request workflow after reviewing the named asset, owner, criticality, compliance and dependencies. In this QA build, requests are recorded for approval only; no system is isolated.'
    elif 'waf' in q:answer=f"{sum(1 for a in assets if a['kind']=='Website' and a['waf']=='Protected')} of {sum(1 for a in assets if a['kind']=='Website')} in-scope websites are marked Protected. This is recorded posture, not independent verification."
    elif 'compliance' in q:answer=f"{sum(1 for a in assets if a['compliance'] is not None and a['compliance']<80)} in-scope assets have recorded compliance below 80%. Null values are unknown, not failures."
    elif any(k in q for k in ('zero day','zeroday','undisclosed')):answer='Open Threats → zero-day signals. The QA backend lists candidate findings without CVEs; these are investigation candidates, not confirmed zero-days.'
    elif any(k in q for k in ('triage','priorit')):answer=f"There are {len(findings)} open findings in scope. The findings endpoint sorts by severity priority, then last update. Use /api/risk/priorities for the transparent risk score and factors."
    else:answer=f"Current scope contains {len(assets)} assets and {len(findings)} open findings. I can answer questions about rescans, findings, priority, compliance, WAF, zero-day candidates, and containment. For unrecognized requests, this QA assistant returns scoped facts and guidance; it is not an LLM and does not invent missing data."
    return {'answer':answer,'mode':'rule-based-qa','sources':['SAM database'],'generatedAt':now(),'scope':body.entity or 'All'}
