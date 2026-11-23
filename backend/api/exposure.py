from typing import Optional
from fastapi import APIRouter,Depends
from backend.core.database import connection
from backend.core.security import current_user
router=APIRouter(prefix='/api/exposure',tags=['attack surface and WAF'])
@router.get('/summary')
def exposure(entity:Optional[str]=None,user=Depends(current_user)):
    with connection() as c:
        filt=' AND kind=?' if entity else '';args=(entity,) if entity else ()
        rows=c.execute("SELECT classification,kind,count(*) n FROM assets WHERE status!='Retired'"+filt+' GROUP BY classification,kind',args).fetchall()
        web=c.execute("SELECT waf,count(*) n FROM assets WHERE kind='Website' AND status!='Retired' GROUP BY waf").fetchall()
    return {'classificationCounts':[dict(x) for x in rows],'wafCounts':[dict(x) for x in web],'verificationNote':'WAF state must come from an approved provider or operator evidence; DNS alone is insufficient.'}
@router.get('/external-assets')
def external_assets(user=Depends(current_user)):
    with connection() as c:rows=c.execute("SELECT a.*,count(f.id) open_findings FROM assets a LEFT JOIN findings f ON f.asset_id=a.id AND f.state IN ('Open','In Progress') WHERE a.classification='External facing' AND a.status!='Retired' GROUP BY a.id ORDER BY a.criticality,open_findings DESC").fetchall()
    return {'items':[dict(x) for x in rows],'source':'SAM asset inventory; not external discovery'}
