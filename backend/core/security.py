from typing import Optional
import base64,hashlib,hmac,json,secrets,time
from datetime import datetime,timedelta,timezone
from fastapi import Depends,HTTPException
from fastapi.security import HTTPAuthorizationCredentials,HTTPBearer
from backend.core.config import MODE,TOKEN_SECRET,TOKEN_TTL_HOURS
from backend.core.database import connection
from backend.core.util import audit
bearer=HTTPBearer(auto_error=False)
def hash_password(p):
    salt=secrets.token_bytes(16); key=hashlib.pbkdf2_hmac('sha256',p.encode(),salt,310000)
    return base64.urlsafe_b64encode(salt+key).decode()
def verify_password(p,encoded):
    try:
        raw=base64.urlsafe_b64decode(encoded); return hmac.compare_digest(raw[16:],hashlib.pbkdf2_hmac('sha256',p.encode(),raw[:16],310000))
    except Exception:return False
def b64(b):return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def issue_token(user):
    secret=TOKEN_SECRET or ('qa-only-change-me' if MODE in {'demo','qa'} else '')
    if not secret:raise HTTPException(503,'SAM_TOKEN_SECRET is not configured')
    now=int(time.time()); h=b64(b'{"alg":"HS256","typ":"JWT"}'); p=b64(json.dumps({'sub':user['id'],'exp':now+TOKEN_TTL_HOURS*3600}).encode()); msg=f'{h}.{p}'
    return f'{msg}.{b64(hmac.new(secret.encode(),msg.encode(),hashlib.sha256).digest())}'
def current_user(auth:Optional[HTTPAuthorizationCredentials]=Depends(bearer)):
    if not auth:raise HTTPException(401,'Bearer token required')
    try:
        h,p,sig=auth.credentials.split('.'); secret=TOKEN_SECRET or ('qa-only-change-me' if MODE in {'demo','qa'} else '')
        msg=f'{h}.{p}'; expected=b64(hmac.new(secret.encode(),msg.encode(),hashlib.sha256).digest())
        claims=json.loads(base64.urlsafe_b64decode(p+'='*((4-len(p)%4)%4)))
        if not secret or not hmac.compare_digest(sig,expected) or claims['exp']<time.time():raise ValueError()
    except Exception:raise HTTPException(401,'Invalid or expired token')
    import hashlib as _h
    with connection() as c:u=c.execute('SELECT u.id,u.email,u.role,u.active FROM users u JOIN sessions s ON s.user_id=u.id WHERE u.id=? AND s.token_hash=? AND s.expires_at>?',(claims['sub'],_h.sha256(auth.credentials.encode()).hexdigest(),datetime.now(timezone.utc).isoformat())).fetchone()
    if not u or not u['active']:raise HTTPException(401,'Session expired or account disabled')
    return dict(u)
def require_roles(*roles):
    def check(user=Depends(current_user)):
        if user['role'] not in roles:raise HTTPException(403,'Insufficient role')
        return user
    return check
def create_session(c,user,token):
    digest=hashlib.sha256(token.encode()).hexdigest(); expires=(datetime.now(timezone.utc)+timedelta(hours=TOKEN_TTL_HOURS)).isoformat()
    c.execute('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)',(digest,user['id'],expires,datetime.now(timezone.utc).isoformat()))
    audit(c,user,'login','session')
