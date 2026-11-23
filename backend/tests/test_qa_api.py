def test_auth_and_asset_paging(client,auth):
    assert client.get('/api/assets').status_code==200
    assert client.get('/api/assets?entity=Website&limit=2',headers=auth).json()['total']==3
    page=client.get('/api/assets?entity=Server&limit=2&offset=1',headers=auth).json()
    assert len(page['items'])==2 and page['offset']==1
    assert client.get('/api/assets').status_code==401

def test_finding_sort_and_dashboard(client,auth):
    findings=client.get('/api/findings',headers=auth).json()['items']
    assert [x['severity'] for x in findings[:2]]==['Critical','Critical']
    dash=client.get('/api/dashboard',headers=auth).json()
    assert dash['assets']==6 and dash['openFindings']==4

def test_priority_sla_and_attack_paths(client,auth):
    priority=client.get('/api/risk/priorities',headers=auth).json()
    assert priority['items'][0]['riskScore']>=priority['items'][-1]['riskScore']
    assert client.get('/api/risk/sla-forecast',headers=auth).json()['breached']
    assert len(client.get('/api/attack-paths',headers=auth).json()['items'])==2

def test_governance_containment_is_simulated(client,auth):
    body={'asset_id':'WEB-1042','action':'Quarantine','acknowledge_impact':True}
    r=client.post('/api/containment/requests',json=body,headers=auth)
    assert r.status_code==202 and r.json()['executionEnabled'] is False
    assert r.json()['status']=='Approval required'
    integrations=client.get('/api/integrations/status',headers=auth).json()
    assert all(x['status']=='pending implementation' for x in integrations['connectors'])
    assert client.post('/api/integrations/qualys/sync',headers=auth).status_code==501

def test_compliance_unknowns_and_analyst(client,auth):
    compliance=client.get('/api/compliance/summary',headers=auth).json()
    assert compliance['assetsEvaluated']==6
    answer=client.post('/api/analyst/ask',json={'question':'How do I request a rescan?'},headers=auth).json()['answer']
    assert 'Rescan workflow' in answer
