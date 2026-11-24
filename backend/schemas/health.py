"""Liveness and readiness response contracts."""

from typing import Literal

from pydantic import BaseModel


class LivenessRead(BaseModel):
    status: Literal["alive"]


class ReadinessRead(BaseModel):
    status: Literal["ready", "ok"]
    mode: str
    database: Literal["connected"]
