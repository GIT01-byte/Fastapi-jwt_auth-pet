from typing import Any, List, Optional

from fastapi import Form
from pydantic import BaseModel, EmailStr, Field


class UserInDB(BaseModel):
    id: int
    username: str
    email: EmailStr | None = None
    hashed_password: bytes
    is_active: bool

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    login: str = Form()
    password: str = Form()


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: Optional[EmailStr] = Field(...)
    profile: Optional[dict[str, Any]] = None
    password: str = Field(..., min_length=8)
