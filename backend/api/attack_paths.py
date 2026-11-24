from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.security import current_user
from backend.schemas.analytics import AttackPathsRead
from backend.services.attack_paths import list_attack_paths

router = APIRouter(prefix="/attack-paths", tags=["attack path analysis"])


@router.get("", response_model=AttackPathsRead)
def paths(user=Depends(current_user), session: Session = Depends(get_db)):
    return list_attack_paths(session)
