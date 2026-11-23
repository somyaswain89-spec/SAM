import os,tempfile
# Set configuration before importing the FastAPI application.
_db=tempfile.NamedTemporaryFile(prefix='sam-qa-',suffix='.db',delete=False)
_db.close()
os.environ['SAM_MODE']='qa'
os.environ['DATABASE_URL']='sqlite:///'+_db.name
os.environ['SAM_ADMIN_EMAIL']='admin@sam.local'
os.environ['SAM_ADMIN_PASSWORD']='demo-access'
os.environ['SAM_TOKEN_SECRET']='qa-test-secret'
import pytest
from fastapi.testclient import TestClient
from backend.app import app

@pytest.fixture
def client():
    with TestClient(app) as c: yield c
@pytest.fixture
def admin_token(client):
    r=client.post('/api/auth/login',json={'email':'admin@sam.local','password':'demo-access'})
    assert r.status_code==200
    return r.json()['access_token']
@pytest.fixture
def auth(admin_token): return {'Authorization':'Bearer '+admin_token}
