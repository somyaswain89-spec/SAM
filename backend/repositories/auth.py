"""Account and session persistence queries."""

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.db.models import PasswordResetToken, RefreshSession, User
from backend.db.models import Session as AccessSession


class AuthRepository:
    def __init__(self, session: Session):
        self.session = session

    def user_by_email(self, email: str) -> User | None:
        return self.session.scalar(select(User).where(User.email == email))

    def active_user_by_email(self, email: str) -> User | None:
        return self.session.scalar(select(User).where(User.email == email, User.active.is_(True)))

    def user_by_id(self, user_id: int) -> User | None:
        return self.session.get(User, user_id)

    def user_by_id_for_update(self, user_id: int) -> User | None:
        return self.session.scalar(select(User).where(User.id == user_id).with_for_update())

    def users_page(self, limit: int, offset: int) -> tuple[list[User], int]:
        users = self.session.scalars(
            select(User).order_by(User.email.asc()).limit(limit).offset(offset)
        ).all()
        total = self.session.scalar(select(func.count()).select_from(User)) or 0
        return list(users), total

    def active_administrator_count_for_update(self) -> int:
        users = self.session.scalars(
            select(User)
            .where(User.role == "admin", User.active.is_(True))
            .order_by(User.id)
            .with_for_update()
        ).all()
        return len(users)

    def user_for_access_token(self, user_id: int, token_hash: str) -> User | None:
        query = (
            select(User)
            .join(AccessSession, AccessSession.user_id == User.id)
            .where(
                User.id == user_id,
                AccessSession.token_hash == token_hash,
                AccessSession.expires_at > datetime.now(UTC).isoformat(),
                AccessSession.revoked_at.is_(None),
                User.active.is_(True),
            )
        )
        return self.session.scalar(query)

    def refresh_by_hash(self, token_hash: str) -> RefreshSession | None:
        return self.session.scalar(
            select(RefreshSession).where(RefreshSession.token_hash == token_hash).with_for_update()
        )

    def reset_by_hash(self, token_hash: str) -> PasswordResetToken | None:
        return self.session.scalar(
            select(PasswordResetToken)
            .where(PasswordResetToken.token_hash == token_hash)
            .with_for_update()
        )

    def access_session_by_hash(self, token_hash: str) -> AccessSession | None:
        return self.session.get(AccessSession, token_hash)

    def reset_token(self, token_hash: str, user_id: int, expires_at: str, created_at: str) -> None:
        self.session.add(
            PasswordResetToken(
                token_hash=token_hash,
                user_id=user_id,
                expires_at=expires_at,
                created_at=created_at,
            )
        )

    def access_session(
        self, token_hash: str, user_id: int, family_id: str, expires_at: str, created_at: str
    ) -> None:
        self.session.add(
            AccessSession(
                token_hash=token_hash,
                user_id=user_id,
                family_id=family_id,
                expires_at=expires_at,
                created_at=created_at,
            )
        )

    def refresh_session(
        self, token_hash: str, user_id: int, family_id: str, expires_at: str, created_at: str
    ) -> None:
        self.session.add(
            RefreshSession(
                token_hash=token_hash,
                user_id=user_id,
                family_id=family_id,
                expires_at=expires_at,
                created_at=created_at,
            )
        )

    def revoke_user_sessions(self, user_id: int, at: str) -> None:
        self.session.query(AccessSession).filter(
            AccessSession.user_id == user_id, AccessSession.revoked_at.is_(None)
        ).update({AccessSession.revoked_at: at}, synchronize_session=False)
        self.session.query(RefreshSession).filter(
            RefreshSession.user_id == user_id, RefreshSession.revoked_at.is_(None)
        ).update({RefreshSession.revoked_at: at}, synchronize_session=False)

    def revoke_refresh_family(self, family_id: str, at: str) -> None:
        self.session.query(RefreshSession).filter(RefreshSession.family_id == family_id).update(
            {RefreshSession.revoked_at: at}, synchronize_session=False
        )

    def create_user(self, *, email: str, password_hash: str, role: str, created_at: str) -> User:
        user = User(email=email, password_hash=password_hash, role=role, created_at=created_at)
        self.session.add(user)
        self.session.flush()
        return user
