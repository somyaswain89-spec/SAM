"""Natural-language analyst request contract."""

from typing import Literal

from pydantic import BaseModel, Field

from backend.schemas.common import AssetType


class AnalystTurn(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=12000)


class AnalystQuestion(BaseModel):
    question: str = Field(min_length=1, max_length=1000)
    entity: AssetType | None = None
    history: list[AnalystTurn] = Field(default_factory=list, max_length=8)


class AnalystAnswer(BaseModel):
    answer: str
    mode: str
    sources: list[str]
    generatedAt: str
    scope: str
    warning: str | None = None
