from fastapi import APIRouter,Depends
from backend.core.database import connection
from backend.core.security import current_user
import json
router=APIRouter(prefix='/api/attack-paths',tags=['attack path analysis'])
@router.get('')
def paths(user=Depends(current_user)):
    # Relations are explicit CMDB attributes; no inferred edge is presented as verified.
    with connection() as c:assets=c.execute('SELECT id,name,kind,criticality,classification,attributes FROM assets WHERE status!=\'Retired\'').fetchall();findings=c.execute("SELECT asset_id,count(*) n,sum(CASE WHEN severity='Critical' THEN 1 ELSE 0 END) critical FROM findings WHERE state IN ('Open','In Progress') GROUP BY asset_id").fetchall()
    risk={x['asset_id']:dict(x) for x in findings};byid={x['id']:x for x in assets};out=[]
    for a in assets:
        try:attrs=json.loads(a['attributes'] or '{}')
        except ValueError:attrs={}
        for target in attrs.get('depends_on',[]):
            b=byid.get(target)
            if b:out.append({'from':{'id':a['id'],'name':a['name']},'to':{'id':b['id'],'name':b['name']},'relationship':'depends_on','source':'asset attributes','verified':True,'riskScore':(risk.get(a['id'],{}).get('critical',0)*25)+(20 if a['classification']=='External facing' else 0)+(20 if b['criticality']=='Critical' else 0)})
    return {'items':sorted(out,key=lambda x:-x['riskScore']),'total':len(out),'note':'Only explicitly recorded depends_on relationships are returned; missing relationships are not inferred.'}
