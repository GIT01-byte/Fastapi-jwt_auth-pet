from datetime import datetime
from typing import Any
from sqlalchemy import DateTime, ForeignKey, Integer, String, Boolean, JSON, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.database import Base


class User(Base):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True)

    username: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    hashed_password: Mapped[bytes] = mapped_column(nullable=False)
    email: Mapped[str | None] = mapped_column(String, unique=True)
    profile: Mapped[Any | None] = mapped_column(JSON)

    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False)

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now())

    user: Mapped[User] = relationship(back_populates="refresh_tokens")
