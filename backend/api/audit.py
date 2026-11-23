from fastapi import APIRouter,Depends,Query
from backend.core.database import connection
from backend.core.security import require_roles
from backend.core.util import dump
router=APIRouter(prefix='/api/audit',tags=['audit'])
@router.get('')
def events(limit:int=Query(100,ge=1,le=1000),user=Depends(require_roles('admin','security_admin','auditor'))):
    with connection() as c:rows=c.execute('SELECT e.*,u.email actor FROM audit_events e LEFT JOIN users u ON u.id=e.user_id ORDER BY e.id DESC LIMIT ?',(limit,)).fetchall()
    return {'items':[dump(x) for x in rows]}
