from datetime import datetime
from typing import Optional
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from models.users import RefreshToken, User
from db.database import Base, async_session_factory, async_engine

from utils.logging import logger


class RefresTokensRepo():
    @staticmethod
    async def create_tables():
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    @staticmethod
    async def create_refresh_token(user_id: int, token_hash: str, expires_at: datetime) -> RefreshToken:
        async with async_session_factory() as session:
            token = RefreshToken(user_id=user_id, token_hash=token_hash, expires_at=expires_at)
            session.add(token)
            await session.flush()
            await session.commit()
            await session.refresh(token)
            return token
    
    @staticmethod
    async def get_refresh_token(token_hash: str) -> Optional[RefreshToken]:
        async with async_session_factory() as session:
            return await session.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))

    @staticmethod
    async def delete_refresh_token(token_obj: RefreshToken) -> None:
        async with async_session_factory() as session:
            await session.delete(token_obj)
