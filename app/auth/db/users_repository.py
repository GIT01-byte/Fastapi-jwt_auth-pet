from typing import Optional
from datetime import datetime

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import EmailStr

from app.auth.deps.auth_deps import SessionDep
from exceptions.exceptions import UserAlreadyExistsError

from db.db_manager import db_manager
from models.users import RefreshToken, User
from models.base import Base

from utils.logging import logger


class UsersRepo():
    @staticmethod
    async def create_tables():
        async with db_manager.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    @staticmethod
    async def create_user(payload: dict) -> Optional[User]:
        async with db_manager.session_factory() as session:
            existing_user = await session.execute(
                select(User)
                .filter(
                    or_(User.username == payload['username'], User.email == payload['email'])
                    )
                )
            if existing_user:
                logger.error(
                    f'User with username: {payload['username']!r} or email: {payload['email']!r} already exists')
                raise UserAlreadyExistsError()
            new_user = User(**payload)
            session.add(new_user)

            await session.flush()
            await session.commit()
            await session.refresh(new_user)
            return new_user

    @staticmethod
    async def select_user_by_user_id(user_id: int) -> User | None:
        async with db_manager.session_factory() as session:
            return await session.scalar(select(User).where(User.id == user_id))

    @staticmethod
    async def select_user_by_useraname(username: str) -> User | None:
        async with db_manager.session_factory() as session:
            return await session.scalar(select(User).where(User.username == username))

    @staticmethod
    async def select_user_by_email(email: EmailStr) -> User | None:
        async with db_manager.session_factory() as session:
            return await session.scalar(select(User).where(User.email == email))


class RefreshTokensRepo():
    @staticmethod
    async def create_tables():
        async with db_manager.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    @staticmethod
    async def create_refresh_token(user_id: int, token_hash: str, expires_at: datetime) -> RefreshToken:
        async with db_manager.session_factory() as session:
            token = RefreshToken(
                user_id=user_id, token_hash=token_hash, expires_at=expires_at)
            session.add(token)
            await session.flush()
            await session.commit()
            await session.refresh(token)
            return token

    @staticmethod
    async def get_refresh_token(token_hash: str) -> Optional[RefreshToken]:
        async with db_manager.session_factory() as session:
            return await session.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))

    @staticmethod
    async def delete_refresh_token(token_obj: RefreshToken) -> None:
        async with db_manager.session_factory() as session:
            await session.delete(token_obj)
