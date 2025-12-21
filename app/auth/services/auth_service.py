from datetime import datetime, timedelta, timezone
from fastapi import Depends, Response
from fastapi.responses import JSONResponse
from jwt.exceptions import InvalidTokenError as JWTInvalidTokenError

from db.users_repository import UsersRepo, RefreshTokensRepo
from config import settings
from schemas.users import UserInDB
from app_redis.client import get_redis_client
from exceptions.exceptions import (
    InvalidPasswordError,
    InvalidTokenError,
    TokenRevokedError,
    UserAlreadyExistsError,
    UserInactiveError,
    UserNotFoundError,
)
from utils.security import (
    ACCESS_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
    check_password,
    create_access_token,
    create_refresh_token as gen_refresh_token,
    hash_password,
)
from deps.auth_deps import (
    oauth2_scheme, 
    set_tokens_cookie,
)

from utils.logging import logger


async def authenticate_user(
    response: Response,
    login: str,
    password: str,
) -> dict:
    user_data_from_db = await UsersRepo.select_user_by_username(login)

    # Проверяем полученного user'а
    if not user_data_from_db:
        raise UserNotFoundError()

    if not check_password(
        password=password,
        hashed_password=user_data_from_db.hashed_password
    ):
        raise InvalidPasswordError()

    if not user_data_from_db.is_active:
        raise UserInactiveError()

    # Преобразуем данные из репозитория в Pydantic модель
    user = UserInDB(
        id=user_data_from_db.id,
        username=user_data_from_db.username,
        email=user_data_from_db.email,
        hashed_password=user_data_from_db.hashed_password,
        is_active=user_data_from_db.is_active,
    )

    # Генерируем токены
    user_id = user.id
    access_token = create_access_token(user_id)
    refresh_token, refresh_hash = gen_refresh_token()

    # Создаем refresh токен
    expires_at = datetime.now(
        timezone.utc) + timedelta(minutes=settings.jwt.refresh_token_expire_days)
    await RefreshTokensRepo.create_refresh_token(user_id, refresh_hash, expires_at)

    # Устанавливаем куки
    set_tokens_cookie(
        key=ACCESS_TOKEN_TYPE,
        value=access_token,
        max_age=settings.jwt.access_token_expire_minutes,
        response=response,
    )
    set_tokens_cookie(
        key=REFRESH_TOKEN_TYPE,
        value=refresh_token,
        max_age=settings.jwt.refresh_token_expire_days,
        response=response,
    )
    return {
        "user": user.username,
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


async def register_user_to_db(
    payload: dict,
    password: str,
) -> str:
    hashed_password = hash_password(password)
    full_payload = {**payload, 'hashed_password': hashed_password}

    created_user_in_db = await UsersRepo.create_user(full_payload)
    if created_user_in_db:
        new_username = created_user_in_db.username
        return new_username
    raise


async def revoke_token(jti: str, expire: int):
    redis = await get_redis_client()
    await redis.setex(f"revoked:{jti}", expire, "1")
