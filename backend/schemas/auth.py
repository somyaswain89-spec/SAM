"""Public authentication and account response contracts."""

from typing import Literal

from pydantic import BaseModel, Field

Role = Literal["admin", "security_admin", "analyst", "auditor", "viewer"]


class UserSummary(BaseModel):
    id: int
    email: str
    role: Role


class UserRead(UserSummary):
    active: bool


class UserPage(BaseModel):
    items: list[UserRead]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)


class UserActiveUpdate(BaseModel):
    active: bool


class UserRoleUpdate(BaseModel):
    role: Role


class SessionResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"]
    expires_in: int
    user: UserSummary


class AccountCreated(BaseModel):
    email: str
    role: Role


class AuthStatus(BaseModel):
    status: str
