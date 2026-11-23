from fastapi import APIRouter,Depends
from backend.core.security import current_user
from backend.api.dashboard import priorities
from backend.core.util import now
router=APIRouter(prefix='/api/risk',tags=['risk and SLA'])
@router.get('/sla-forecast')
def sla_forecast(user=Depends(current_user)):
    items=priorities(None,500,user)['items'];breached=[];at_risk=[]
    for f in items:
        due=f.get('due_at')
        if not due:continue
        from datetime import datetime,timezone
        try:days=(datetime.fromisoformat(due.replace('Z','+00:00'))-datetime.now(timezone.utc)).total_seconds()/86400
        except ValueError:continue
        row={'findingId':f['id'],'title':f['title'],'assetId':f['asset_id'],'dueAt':due,'daysRemaining':round(days,1)}
        if days<0:breached.append(row)
        elif days<=7:at_risk.append(row)
    return {'breached':breached,'atRiskNext7Days':at_risk,'evaluatedAt':now(),'forecastMethod':'Due-date deterministic rule; no predictive model or assumed SLA is applied.'}
