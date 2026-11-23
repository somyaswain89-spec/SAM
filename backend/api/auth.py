from typing import Optional
from fastapi import APIRouter,Depends,HTTPException
from datetime import datetime,timezone
import hashlib
from backend.core.database import connection
from backend.core.config import BOOTSTRAP_EMAIL,BOOTSTRAP_PASSWORD,TOKEN_TTL_HOURS
from backend.core.security import current_user,hash_password,verify_password,issue_token,create_session,bearer
from backend.core.util import audit
from backend.schemas.common import Login
from fastapi.security import HTTPAuthorizationCredentials
router=APIRouter(prefix='/api/auth',tags=['authentication'])
@router.post('/login')
def login(body:Login):
    with connection() as c:user=c.execute('SELECT * FROM users WHERE email=?',(body.email.lower(),)).fetchone()
    if not user or not user['active'] or not verify_password(body.password,user['password_hash']):raise HTTPException(401,'Invalid email or password')
    token=issue_token(user)
    with connection() as c:create_session(c,dict(user),token)
    return {'access_token':token,'token_type':'bearer','expires_in':TOKEN_TTL_HOURS*3600,'user':{'email':user['email'],'role':user['role']}}
@router.get('/me')
def me(user=Depends(current_user)):return user
@router.post('/logout')
def logout(auth:Optional[HTTPAuthorizationCredentials]=Depends(bearer),user=Depends(current_user)):
    with connection() as c:
        c.execute('DELETE FROM sessions WHERE token_hash=?',(hashlib.sha256(auth.credentials.encode()).hexdigest(),));audit(c,user,'logout','session')
    return {'status':'signed_out'}
@router.post('/users',status_code=201)
def create_user(body:Login,role:str='analyst',user=Depends(current_user)):
    if user['role']!='admin':raise HTTPException(403,'Admin role required')
    if role not in {'admin','security_admin','analyst','auditor','viewer'}:raise HTTPException(422,'Invalid role')
    with connection() as c:
        try:c.execute('INSERT INTO users(email,password_hash,role,created_at) VALUES(?,?,?,?)',(body.email.lower(),hash_password(body.password),role,datetime.now(timezone.utc).isoformat()))
        except Exception:raise HTTPException(409,'Email already exists')
        audit(c,user,'user.create','user',body.email,{'role':role})
    return {'email':body.email.lower(),'role':role}
