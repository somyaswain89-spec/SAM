from fastapi import APIRouter,Depends,HTTPException
from backend.core.database import connection
from backend.core.security import current_user,require_roles
from backend.core.config import MODE
router=APIRouter(prefix='/api/integrations',tags=['integrations'])
@router.get('/status')
def status(user=Depends(current_user)):
    with connection() as c:runs=[dict(x) for x in c.execute('SELECT * FROM sync_runs ORDER BY started_at DESC LIMIT 20').fetchall()]
    return {'mode':MODE,'connectors':[{'name':'Qualys VMDR','status':'pending implementation','configured':False},{'name':'ServiceNow CMDB','status':'pending implementation','configured':False}],'recentRuns':runs,'note':'No data is fetched until the source connector is implemented and explicitly configured.'}
@router.post('/{source}/sync',status_code=501)
def sync(source:str,user=Depends(require_roles('admin','security_admin'))):
    if source not in ('qualys','servicenow'):raise HTTPException(404,'Unknown connector')
    raise HTTPException(501,'Source connector is pending; no remote request was made')
