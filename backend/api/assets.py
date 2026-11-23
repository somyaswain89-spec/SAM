from typing import Optional
from fastapi import APIRouter,Depends,HTTPException,Query
from backend.core.database import connection
from backend.core.security import current_user,require_roles
from backend.core.util import now,dump,audit
from backend.schemas.common import AssetCreate,AssetUpdate
router=APIRouter(prefix='/api/assets',tags=['asset inventory'])
@router.get('')
def list_assets(entity:Optional[str]=None,classification:Optional[str]=None,status:Optional[str]=None,q:Optional[str]=Query(None,max_length=200),sort:str='name',direction:str='asc',limit:int=Query(100,ge=1,le=500),offset:int=Query(0,ge=0),user=Depends(current_user)):
    if entity and entity not in ('Website','Server'):raise HTTPException(422,'entity must be Website or Server')
    allowed={'name','criticality','compliance','updated_at','kind'}
    if sort not in allowed or direction not in ('asc','desc'):raise HTTPException(422,'Unsupported sort')
    clauses=[];args=[]
    for col,val in [('kind',entity),('classification',classification),('status',status)]:
        if val:clauses.append(f'{col}=?');args.append(val)
    if q:clauses.append('(name LIKE ? OR id LIKE ? OR owner LIKE ?)');args.extend([f'%{q}%']*3)
    where=' WHERE '+' AND '.join(clauses) if clauses else ''
    with connection() as c:
        total=c.execute('SELECT count(*) FROM assets'+where,args).fetchone()[0]
        rows=c.execute(f'SELECT * FROM assets{where} ORDER BY {sort} {direction.upper()}, id LIMIT ? OFFSET ?',(*args,limit,offset)).fetchall()
    return {'items':[dump(r) for r in rows],'total':total,'limit':limit,'offset':offset,'sort':sort,'direction':direction}
@router.post('',status_code=201)
def create_asset(body:AssetCreate,user=Depends(require_roles('admin','security_admin','analyst'))):
    t=now()
    with connection() as c:
        try:c.execute('INSERT INTO assets(id,name,kind,classification,owner,environment,criticality,compliance,status,waf,attributes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(body.id,body.name,body.kind,body.classification,body.owner,body.environment,body.criticality,body.compliance,'Active',body.waf,__import__('json').dumps(body.attributes),t,t))
        except Exception:raise HTTPException(409,'Asset ID already exists')
        audit(c,user,'asset.create','asset',body.id,body.model_dump());return dump(c.execute('SELECT * FROM assets WHERE id=?',(body.id,)).fetchone())
@router.get('/{asset_id}')
def asset_detail(asset_id:str,user=Depends(current_user)):
    with connection() as c:
        a=c.execute('SELECT * FROM assets WHERE id=?',(asset_id,)).fetchone()
        if not a:raise HTTPException(404,'Asset not found')
        d=dump(a);d['findings']=[dump(x) for x in c.execute("SELECT * FROM findings WHERE asset_id=? ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, updated_at DESC",(asset_id,))];return d
@router.patch('/{asset_id}')
def update_asset(asset_id:str,body:AssetUpdate,user=Depends(require_roles('admin','security_admin','analyst'))):
    data=body.model_dump(exclude_unset=True)
    if any(k in data and data[k] is None for k in ('name','classification','owner','environment','criticality','status','attributes')):raise HTTPException(422,'This field cannot be null')
    if not data:raise HTTPException(400,'No update fields supplied')
    import json
    if 'attributes' in data:data['attributes']=json.dumps(data['attributes'])
    data['updated_at']=now()
    with connection() as c:
        if not c.execute('SELECT 1 FROM assets WHERE id=?',(asset_id,)).fetchone():raise HTTPException(404,'Asset not found')
        c.execute('UPDATE assets SET '+','.join(f'{k}=?' for k in data)+' WHERE id=?',(*data.values(),asset_id));audit(c,user,'asset.update','asset',asset_id,data)
        return dump(c.execute('SELECT * FROM assets WHERE id=?',(asset_id,)).fetchone())
