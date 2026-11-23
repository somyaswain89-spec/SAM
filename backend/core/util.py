import json
from datetime import datetime,timezone

def now(): return datetime.now(timezone.utc).isoformat()
def dump(row):
    if row is None:return None
    d=dict(row)
    for key in ('attributes','evidence','detail','payload'):
        if key in d and isinstance(d[key],str):
            try:d[key]=json.loads(d[key])
            except ValueError:pass
    return d
def audit(c,user,action,kind,object_id=None,detail=None):
    c.execute('INSERT INTO audit_events(user_id,action,object_type,object_id,detail,created_at) VALUES(?,?,?,?,?,?)',(user['id'] if user else None,action,kind,object_id,json.dumps(detail or {}),now()))
