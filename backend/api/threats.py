from fastapi import APIRouter,Depends
from backend.core.database import connection
from backend.core.security import current_user
from backend.core.util import now,dump
router=APIRouter(prefix='/api/threats',tags=['threat intelligence'])
@router.get('/zero-day-signals')
def zero_day_signals(user=Depends(current_user)):
    with connection() as c:
        signals=[dump(x) for x in c.execute('SELECT * FROM zero_day_signals ORDER BY created_at DESC').fetchall()]
        candidates=c.execute("SELECT f.id finding_id,f.title,f.severity,a.id asset_id,a.name,a.kind,a.owner,a.criticality FROM findings f JOIN assets a ON a.id=f.asset_id WHERE f.state IN ('Open','In Progress') AND (f.cve IS NULL OR f.cve='') ORDER BY CASE f.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 ELSE 2 END").fetchall()
        all_candidates={x['finding_id']:dict(x) for x in c.execute("SELECT f.id finding_id,f.title,f.severity,a.id asset_id,a.name,a.kind,a.owner,a.criticality FROM findings f JOIN assets a ON a.id=f.asset_id WHERE f.state IN ('Open','In Progress')").fetchall()}
    for signal in signals:
        ids=signal.get('evidence',{}).get('finding_ids',[])
        signal['impactedAssets']=[all_candidates[i] for i in ids if i in all_candidates]
    return {'signals':signals,'candidateFindings':[dict(x) for x in candidates],'warning':'A suspected signal is not confirmation of a zero-day; validate evidence and affected versions.'}
