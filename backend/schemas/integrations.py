"""Public response contracts for source connector operations."""

from typing import Literal

from pydantic import BaseModel

ConnectorId = Literal["qualys", "servicenow", "threat_intel"]
ConnectorState = Literal["configured", "unconfigured"]


class ConnectorRead(BaseModel):
    id: ConnectorId
    name: str
    status: ConnectorState
    configured: bool
    capabilities: list[str]
    tables: list[str] | None = None


class SyncRunRead(BaseModel):
    id: str
    source: ConnectorId
    status: Literal["queued", "running", "completed", "failed"]
    started_at: str
    finished_at: str | None = None
    records_read: int
    records_written: int
    error: str | None = None


class IntegrationStatusRead(BaseModel):
    connectors: list[ConnectorRead]
    recentRuns: list[SyncRunRead]
    note: str
    ticketWriteConfigured: bool = False
    aiAnalystConfigured: bool = False


class SyncRunCreated(SyncRunRead):
    task_id: str


class SyncRunPage(BaseModel):
    items: list[SyncRunRead]
    total: int
    limit: int
    offset: int


class ConnectionTestRead(BaseModel):
    ok: bool
    provider: str
