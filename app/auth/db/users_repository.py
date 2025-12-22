
# Например, db/repos/users_repo.py (или где у вас находятся UsersRepo и RefreshTokensRepo)

from typing import Optional
from datetime import datetime

from sqlalchemy import or_, select, delete
from sqlalchemy.exc import SQLAlchemyError # Импортируем для обработки специфичных ошибок SQLAlchemy
from pydantic import EmailStr

# Импортируем наши обновленные исключения
from exceptions.exceptions import (
    UserAlreadyExistsError,
    EntityNotFoundError,
    RepositoryInternalError
)

from db.db_manager import db_manager
from models.users import RefreshToken, User

from utils.logging import logger


class UsersRepo:
    @staticmethod
    async def create_user(payload: dict) -> Optional[User]:
        username = payload.get('username')
        email = payload.get('email')
        logger.debug(f"Попытка создания пользователя с username: {username!r}, email: {email!r}")
        try:
            async with db_manager.session_factory() as session:
                existing_user = await session.scalar(
                    select(User)
                    .filter(
                        or_(User.username == username, User.email == email)
                    )
                )
                if existing_user:
                    error_msg = f'Пользователь с username: {username!r} или email: {email!r} уже существует.'
                    logger.error(error_msg)
                    raise UserAlreadyExistsError(error_msg)
                
                new_user = User(**payload)
                session.add(new_user)

                await session.flush()
                await session.commit()
                await session.refresh(new_user)
                logger.info(f"Пользователь ID:{new_user.id}, username:{new_user.username!r} успешно создан.")
                return new_user
        except UserAlreadyExistsError:
            raise
        except SQLAlchemyError as e:
            logger.exception(f"Ошибка базы данных при создании пользователя {username!r}: {e}")
            raise RepositoryInternalError("Не удалось создать пользователя из-за ошибки базы данных.") from e
        except Exception as e:
            logger.exception(f"Неожиданная ошибка при создании пользователя {username!r}: {e}")
            raise RepositoryInternalError("Не удалось создать пользователя из-за неожиданной ошибки.") from e

    @staticmethod
    async def select_user_by_user_id(user_id: int) -> User | None:
        logger.debug(f"Попытка выбрать пользователя по ID: {user_id}")
        try:
            async with db_manager.session_factory() as session:
                user = await session.scalar(select(User).where(User.id == user_id))
                if not user:
                    # Можно выбрать, возвращать None или поднимать NotFoundError
                    # Здесь я поднимаю, чтобы показать обработку
                    logger.debug(f"Пользователь с ID: {user_id} не найден.")
                    raise EntityNotFoundError(f"Пользователь с ID {user_id} не найден.")
                logger.debug(f"Найден пользователь ID: {user_id}, username: {user.username!r}.")
                return user
        except EntityNotFoundError:
            raise # Перебрасываем, если не найден
        except SQLAlchemyError as e:
            logger.exception(f"Ошибка базы данных при выборе пользователя по ID {user_id}: {e}")
            raise RepositoryInternalError("Не удалось выбрать пользователя по ID из-за ошибки базы данных.") from e
        except Exception as e:
            logger.exception(f"Неожиданная ошибка при выборе пользователя по ID {user_id}: {e}")
            raise RepositoryInternalError("Не удалось выбрать пользователя по ID из-за неожиданной ошибки.") from e

    @staticmethod
    async def select_user_by_username(username: str) -> User | None:
        logger.debug(f"Попытка выбрать пользователя по username: {username!r}")
        try:
            async with db_manager.session_factory() as session:
                user = await session.scalar(select(User).where(User.username == username))
                if not user:
                    logger.debug(f"Пользователь с username: {username!r} не найден.")
                    raise EntityNotFoundError(f"Пользователь с username {username!r} не найден.")
                logger.debug(f"Найден пользователь с username: {username!r}, ID: {user.id}.")
                return user
        except EntityNotFoundError:
            raise
        except SQLAlchemyError as e:
            logger.exception(f"Ошибка базы данных при выборе пользователя по username {username!r}: {e}")
            raise RepositoryInternalError("Не удалось выбрать пользователя по username из-за ошибки базы данных.") from e
        except Exception as e:
            logger.exception(f"Неожиданная ошибка при выборе пользователя по username {username!r}: {e}")
            raise RepositoryInternalError("Не удалось выбрать пользователя по username из-за неожиданной ошибки.") from e

    @staticmethod
    async def select_user_by_email(email: EmailStr) -> User | None:
        logger.debug(f"Попытка выбрать пользователя по email: {email!r}")
        try:
            async with db_manager.session_factory() as session:
                user = await session.scalar(select(User).where(User.email == email))
                if not user:
                    logger.debug(f"Пользователь с email: {email!r} не найден.")
                    raise EntityNotFoundError(f"Пользователь с email {email!r} не найден.")
                logger.debug(f"Найден пользователь с email: {email!r}, ID: {user.id}.")
                return user
        except EntityNotFoundError:
            raise
        except SQLAlchemyError as e:
            logger.exception(f"Ошибка базы данных при выборе пользователя по email {email!r}: {e}")
            raise RepositoryInternalError("Не удалось выбрать пользователя по email из-за ошибки базы данных.") from e
        except Exception as e:
            logger.exception(f"Неожиданная ошибка при выборе пользователя по email {email!r}: {e}")
            raise RepositoryInternalError("Не удалось выбрать пользователя по email из-за неожиданной ошибки.") from e


class RefreshTokensRepo:
    @staticmethod
    async def create_refresh_token(user_id: int, token_hash: str, expires_at: datetime) -> RefreshToken:
        logger.debug(f"Попытка создания refresh токена для user_id: {user_id}")
        try:
            async with db_manager.session_factory() as session:
                token = RefreshToken(
                    user_id=user_id, token_hash=token_hash, expires_at=expires_at)
                session.add(token)
                await session.flush()
                await session.commit()
                await session.refresh(token)
                logger.info(f"Refresh токен ID:{token.id} для user_id:{user_id} успешно создан.")
                return token
        except SQLAlchemyError as e:
            logger.exception(f"Ошибка базы данных при создании refresh токена для user_id {user_id}: {e}")
            raise RepositoryInternalError("Не удалось создать refresh токен из-за ошибки базы данных.") from e
        except Exception as e:
            logger.exception(f"Неожиданная ошибка при создании refresh токена для user_id {user_id}: {e}")
            raise RepositoryInternalError("Не удалось создать refresh токен из-за неожиданной ошибки.") from e

    @staticmethod
    async def get_refresh_token(token_hash: str) -> Optional[RefreshToken]:
        logger.debug("Попытка получить refresh токен по хэшу (первые 8 символов): %s...", token_hash[:8])
        try:
            async with db_manager.session_factory() as session:
                token = await session.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
                if not token:
                    logger.debug("Refresh токен по заданному хэшу не найден.")
                    raise EntityNotFoundError("Refresh токен не найден.")
                logger.debug(f"Найден refresh токен ID:{token.id} для user_id:{token.user_id}.")
                return token
        except EntityNotFoundError:
            raise
        except SQLAlchemyError as e:
            logger.exception(f"Ошибка базы данных при получении refresh токена (хэш: {token_hash[:8]}...): {e}")
            raise RepositoryInternalError("Не удалось получить refresh токен из-за ошибки базы данных.") from e
        except Exception as e:
            logger.exception(f"Неожиданная ошибка при получении refresh токена (хэш: {token_hash[:8]}...): {e}")
            raise RepositoryInternalError("Не удалось получить refresh токен из-за неожиданной ошибки.") from e

    @staticmethod
    async def invalidate_all_refresh_tokens(user_id: int) -> None:
        logger.debug(f"Попытка аннулировать все refresh токены для user_id: {user_id}")
        try:
            async with db_manager.session_factory() as session:
                query = (
                    delete(RefreshToken)
                    .where(RefreshToken.user_id == user_id)
                )
                result = await session.execute(query)
                await session.commit()
                logger.info(f"Успешно аннулировано {result.rowcount} refresh токенов для user_id: {user_id}.") # type: ignore
        except SQLAlchemyError as e:
            logger.exception(f"Ошибка базы данных при аннулировании refresh токенов для user_id {user_id}: {e}")
            raise RepositoryInternalError("Не удалось аннулировать refresh токены из-за ошибки базы данных.") from e
        except Exception as e:
            logger.exception(f"Неожиданная ошибка при аннулировании refresh токенов для user_id {user_id}: {e}")
            raise RepositoryInternalError("Не удалось аннулировать refresh токены из-за неожиданной ошибки.") from e

