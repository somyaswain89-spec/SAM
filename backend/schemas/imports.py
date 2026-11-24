"""Typed response contracts for asynchronous import and export jobs."""

from pydantic import BaseModel, Field


class ImportRowError(BaseModel):
    row: int | None = None
    error: str


class ImportJobRead(BaseModel):
    id: str
    jobType: str
    source: str
    status: str
    filename: str
    totalRows: int = Field(ge=0)
    processedRows: int = Field(ge=0)
    rejectedRows: int = Field(ge=0)
    errors: list[ImportRowError]
    createdAt: str
    updatedAt: str
    downloadAvailable: bool


class ImportJobPage(BaseModel):
    items: list[ImportJobRead]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)


class ImportJobAccepted(BaseModel):
    job: ImportJobRead
    statusUrl: str
