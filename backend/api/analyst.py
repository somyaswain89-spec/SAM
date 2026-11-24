"""Authenticated natural-language security analyst API."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.security import current_user
from backend.schemas.analyst import AnalystAnswer, AnalystQuestion
from backend.services.analyst import answer_question

router = APIRouter(prefix="/analyst", tags=["analyst"])


@router.post("/ask", response_model=AnalystAnswer)
def ask(payload: AnalystQuestion, user=Depends(current_user), session: Session = Depends(get_db)):
    return answer_question(
        session,
        question=payload.question,
        entity=payload.entity,
        history=[turn.model_dump() for turn in payload.history],
    )
