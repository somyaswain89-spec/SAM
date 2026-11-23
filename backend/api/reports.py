from fastapi import APIRouter,Depends
from backend.core.security import current_user
from backend.api.dashboard import dashboard
from backend.api.findings import list_findings
from backend.api.compliance import summary
from backend.core.util import now
router=APIRouter(prefix='/api/reports',tags=['reports'])
@router.get('/executive')
def executive(user=Depends(current_user)):
    return {'reportType':'Executive security posture','generatedAt':now(),'dashboard':dashboard(None,user),'compliance':summary(None,90,user),'topFindings':list_findings(sort='risk',direction='desc',limit=10,offset=0,user=user)['items']}
