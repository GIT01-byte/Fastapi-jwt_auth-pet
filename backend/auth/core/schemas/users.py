from datetime import datetime
from typing import Annotated, Any, List, Optional

from fastapi import Form
from pydantic import BaseModel, EmailStr, Field


class UserRead(BaseModel):
    id: int
    username: str
    email: Annotated[EmailStr, None]
    is_active: bool

    model_config = {
        "from_attributes": True
    }


class JWTPayload(BaseModel):
    sub: str
    exp: datetime
    jti: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class LoginRequest(BaseModel):
    login: str = Form()
    password: str = Form()


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: Optional[EmailStr] = Field(...)
    profile: Optional[dict[str, Any]] = None
    password: str = Field(..., min_length=8)
