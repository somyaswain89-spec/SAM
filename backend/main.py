"""SAM demo application. All data and actions are simulated."""
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SAM Security Exposure Platform", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:8765", "http://localhost:8765"], allow_methods=["GET"], allow_headers=["Content-Type"])

@app.get("/")
def index():
    return FileResponse(Path(__file__).resolve().parent.parent / "frontend" / "index.html", media_type="text/html", headers={"Cache-Control": "no-store"})

@app.get("/api/health")
def health():
    return {"status": "ok", "mode": "demo", "productionReady": False, "actionsEnabled": False}
