import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from fastapi import Depends, Response
from fastapi.security import OAuth2PasswordBearer
from redis import Redis
from jwt import PyJWTError

from core.app_redis.client import get_redis_client
from core.db.repositories import UsersRepo
from exceptions.exceptions import (
    InvalidTokenError,
    SetCookieFailedError,
    AccessTokenRevokedError,
    UserInactiveError,
    UserNotFoundError,
)
from utils.security import (
    REFRESH_TOKEN_TYPE,
    ACCESS_TOKEN_TYPE,
    decode_access_token,
)

from core.settings import settings
from utils.logging import logger
from utils.time_decorator import time_all_methods, sync_timed_report, async_timed_report

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/login/")


@sync_timed_report()
def clear_cookie_with_tokens(response: Response) -> Response:
    """
    Очищает куки с токенами из ответа.

    :param response: Объект Response FastAPI для установки куки
    :return: Модифицированный ответ
    """
    response.delete_cookie(ACCESS_TOKEN_TYPE)
    response.delete_cookie(REFRESH_TOKEN_TYPE)

    return response


@sync_timed_report()
def set_tokens_cookie(response: Response, access_token: str, refresh_token: str):
    """
    Устанавливает и обновляет токены в куки с настройками безопасности.

    :param access_token: Access токен для установки
    :param access_token: Refresh токен для установки
    :param response: Объект Response FastAPI для установки куки
    :raise SetCookieFailedError: Если установка куки прошла неудачно
    """
    try:
        # 1. Очищаем куки
        clear_cookie_with_tokens(response=response)

        # 2. Устанавляиваем токены в куки
        response.set_cookie(
            key=ACCESS_TOKEN_TYPE,
            value=access_token,
            httponly=True,  # Доступно только через HTTP
            secure=True,  # Используется только по HTTPS
            samesite="strict",  # Предотвращение межсайтового отслеживания
            max_age=settings.jwt.access_token_expire_minutes * 60,
        )
        response.set_cookie(
            key=REFRESH_TOKEN_TYPE,
            value=refresh_token,
            httponly=True,  # Доступно только через HTTP
            secure=True,  # Используется только по HTTPS
            samesite="strict",  # Предотвращение межсайтового отслеживания
            max_age=settings.jwt.refresh_token_expire_days * 60,
        )
    except Exception as exc:
        logger.error(f"Ошибка установки куки: {exc}")
        raise SetCookieFailedError() from exc


@async_timed_report()
async def get_current_user_from_token(
    token: str = Depends(oauth2_scheme),
    redis: Redis = Depends(get_redis_client),
) -> dict:
    """
    Возвращает текущего активного пользователя на основании JWT-токена.

    :param token: JWT-токен
    :param redis: Клиент Redis для хранения черных списков
    :raises InvalidTokenError: Если токен недействителен
    :raises AccessTokenRevokedError: Если токен аннулирован
    :raises UserNotFoundError: Если пользователь не найден
    :return: Словарь с данными текущего пользователя, jti (уникального ID JWT-токена), iat (время последнего входа в систему)
    """
    try:
        payload = decode_access_token(token)

        jti: str | None = payload.get("jti")
        user_id: int | None = int(payload.get("sub"))  # type: ignore
        iat: int | None = payload.get("iat")

        if not user_id or not jti:
            raise InvalidTokenError("Missing required claims: sub or jti")

        # Проверка чёрного списка Redis
        if await redis.exists(f"blacklist:access:{jti}"):
            raise AccessTokenRevokedError()

        # Запрашиваем пользователя из базы данных
        user = await UsersRepo.select_user_by_user_id(user_id)

        # Проверяем полученного user'а
        if not user:
            raise UserNotFoundError()

        return {
            "jti": jti,
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "is_active": user.is_active,
            "iat": iat,
        }

    except PyJWTError as err:
        logger.error(f"Ошибка декодирования токена: {err}")
        raise InvalidTokenError()


@async_timed_report()
async def get_current_active_user(current_user: dict = Depends(get_current_user_from_token)):
    """
    Возвращает активного пользователя.

    :param current_user: Пользователь из зависимости get_current_user_from_token
    :raises UserInactiveError: Если пользователь неактивен
    :return: Активный пользователь
    """
    if current_user["is_active"] == True:
        return current_user
    raise UserInactiveError()
