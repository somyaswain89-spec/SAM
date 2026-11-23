from typing import Optional
from fastapi import APIRouter,Depends,Query
from backend.core.database import connection
from backend.core.security import current_user
from backend.core.util import now
router=APIRouter(prefix='/api/compliance',tags=['compliance'])
@router.get('/summary')
def summary(entity:Optional[str]=None,target:int=Query(90,ge=1,le=100),user=Depends(current_user)):
    with connection() as c:
        rows=c.execute('SELECT id,name,kind,owner,compliance FROM assets WHERE compliance IS NOT NULL'+(' AND kind=?' if entity else ''),((entity,) if entity else ())).fetchall()
    scores=[r['compliance'] for r in rows]; avg=round(sum(scores)/len(scores),1) if scores else None
    return {'assetsEvaluated':len(scores),'averagePercent':avg,'targetPercent':target,'belowTarget':sum(x<target for x in scores),'unknownAssets':None,'method':'Mean of explicitly recorded asset compliance scores; no policy evaluation is inferred.','calculatedAt':now()}
@router.get('/assets')
def compliance_assets(entity:Optional[str]=None,user=Depends(current_user)):
    with connection() as c: rows=c.execute('SELECT id,name,kind,owner,compliance FROM assets'+(' WHERE kind=?' if entity else '')+' ORDER BY compliance ASC',(entity,) if entity else ()).fetchall()
    return {'items':[dict(x) for x in rows],'sortRule':'lowest known compliance first; NULL scores remain unknown'}
