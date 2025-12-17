from typing import Optional

from sqlalchemy import select
from pydantic import EmailStr

from exceptions.exceptions import UserAlreadyExistsError
from models.users import User
from db.database import Base, async_session_factory, async_engine

from utils.logging import logger


class UsersRepo():
    @staticmethod
    async def create_tables():
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    @staticmethod
    async def create_user(payload: dict) -> Optional[User]:
        async with async_session_factory() as session:
            existing_username = await UsersRepo.select_user_by_useraname(payload['username'])
            existing_email = await UsersRepo.select_user_by_email(payload['email'])
            if existing_username or existing_email:
                logger.error(f'User with username: {payload['username']!r} or email: {payload['email']!r} already exists')
                raise UserAlreadyExistsError()
            new_user = User(**payload)
            session.add(new_user)

            await session.flush()
            await session.commit()
            await session.refresh(new_user)
            return new_user

    @staticmethod
    async def select_user_by_user_id(user_id: int) -> User | None:
        async with async_session_factory() as session:
            return await session.scalar(select(User).where(User.id == user_id))

    @staticmethod
    async def select_user_by_useraname(username: str) -> User | None:
        async with async_session_factory() as session:
            return await session.scalar(select(User).where(User.username == username))

    @staticmethod
    async def select_user_by_email(email: EmailStr) -> User | None:
        async with async_session_factory() as session:
            return await session.scalar(select(User).where(User.email == email))
