# SAM
SAM RFP

---

# SAM Security Exposure Platform

A redesigned local demo for unified website and server exposure management. It includes a sign-in screen, an all-estate dashboard, website/server views, an asset inventory with internal/external classifications, vulnerability prioritization, compliance dashboards, website WAF posture, response workflows, integrations readiness, and simulated server quarantine controls.

## Run locally

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.main:app --host 127.0.0.1 --port 8765
```

Open http://127.0.0.1:8765. The sign-in is a front-end demonstration only: any non-empty email and password work. The interface also works by opening `frontend/index.html` directly.

## Demo limitations

All assets, vulnerabilities, compliance percentages, check-in times, integrations and actions are fictional. There is no real authentication, active scanning, WAF verification, cloud or CMDB connection, ticket creation, quarantine, shutdown, or infrastructure change. Buttons that represent operational actions only update demo UI state or show guidance. Do not use this demo with real assets or expose it as a production security boundary.
