"""SAM application factory and API composition."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from backend.core.config import ROOT,MODE,CORS_ORIGINS,BOOTSTRAP_EMAIL,BOOTSTRAP_PASSWORD
from backend.core.database import initialize_schema,connection
from backend.core.security import hash_password
from backend.core.util import now
from backend.api import auth,assets,findings,dashboard,compliance,governance,exposure,threats,attack_paths,integrations,audit,risk,reports,analyst
from datetime import datetime,timedelta,timezone

def seed_qa_data():
    if MODE not in {'demo','qa'}:return
    t=now()
    with connection() as c:
        if not c.execute('SELECT 1 FROM users LIMIT 1').fetchone():c.execute('INSERT INTO users(email,password_hash,role,created_at) VALUES(?,?,?,?)',(BOOTSTRAP_EMAIL,hash_password(BOOTSTRAP_PASSWORD), 'admin',t))
        if c.execute('SELECT 1 FROM assets LIMIT 1').fetchone():return
        sample=[('WEB-1042','customer-portal.acme.test','Website','External facing','Digital Experience','Production','Critical',72,'Protected',{'depends_on':['SRV-2201']}),('WEB-1048','staff.acme.test','Website','Internal facing','Corporate IT','Production','High',91,'Unknown',{}),('WEB-1071','api.acme.test','Website','External facing','Platform Engineering','Production','Critical',64,'Unverified',{}),('SRV-2201','prod-app-01','Server','External facing','Platform Engineering','Production','Critical',68,None,{'depends_on':['SRV-2208']}),('SRV-2208','corp-ad-02','Server','Internal facing','Corporate IT','Production','Critical',88,None,{}),('SRV-2233','analytics-stage-03','Server','Internal facing','Data Platform','Staging','Medium',43,None,{})]
        import json
        for a in sample:c.execute('INSERT INTO assets(id,name,kind,classification,owner,environment,criticality,compliance,status,waf,attributes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(*a[:8],'Active',a[8],json.dumps(a[9]),t,t))
        vulns=[('FND-8012','WEB-1042','Remote code execution in runtime','CVE-2026-1842','Critical',0.91,True),('FND-8016','WEB-1071','Authentication bypass','CVE-2026-2031','Critical',0.78,True),('FND-7894','SRV-2201','Kernel privilege escalation','CVE-2026-0441','High',0.66,False),('FND-7880','SRV-2233','Missing security update','CVE-2026-1322','High',0.18,False)]
        due_offsets=[-2,3,14,9]
        for f,days in zip(vulns,due_offsets):
            due=(datetime.now(timezone.utc)+timedelta(days=days)).isoformat()
            c.execute('INSERT INTO findings(id,asset_id,title,cve,severity,first_seen,last_seen,due_at,evidence,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(*f[:5],t,t,due,json.dumps({'epss':f[5],'kev':f[6]}),t,t))
        c.execute('INSERT INTO zero_day_signals(id,title,severity,confidence,status,source,evidence,created_at) VALUES(?,?,?,?,?,?,?,?)',('ZD-QA-001','Undisclosed runtime behavior candidate','Critical','Medium','Needs validation','QA synthetic signal',json.dumps({'finding_ids':['FND-8012','FND-8016']}),t))

def create_app():
    application=FastAPI(title='SAM Security Exposure API',version='2.0.0',docs_url='/api/docs' if MODE in {'demo','qa'} else None,redoc_url=None)
    application.add_middleware(CORSMiddleware,allow_origins=CORS_ORIGINS,allow_methods=['GET','POST','PATCH','DELETE'],allow_headers=['Authorization','Content-Type'])
    for r in [auth.router,assets.router,findings.router,dashboard.router,compliance.router,governance.router,exposure.router,threats.router,attack_paths.router,integrations.router,audit.router,risk.router,reports.router,analyst.router]:application.include_router(r)
    @application.on_event('startup')
    def startup():initialize_schema();seed_qa_data()
    @application.get('/')
    def frontend():return FileResponse(ROOT/'frontend'/'index.html',media_type='text/html',headers={'Cache-Control':'no-store'})
    @application.get('/api/health',tags=['operations'])
    def health():
        with connection() as c:c.execute('SELECT 1')
        return {'status':'ok','mode':MODE,'database':'connected','integrations':'pending'}
    return application
app=create_app()
