from typing import Dict
from fastapi import Depends, Request, Response
from fastapi.security import OAuth2PasswordBearer
from redis import Redis
from jwt import PyJWTError

from app_redis.client import get_redis_client
from db.users_repository import UsersRepo
from utils.security import (
    REFRESH_TOKEN_TYPE,
    ACCESS_TOKEN_TYPE,
    decode_access_token,
)
from exceptions.exceptions import (
    CookieMissingTokenError,
    InvalidTokenError,
    SetCookieFailedError,
    TokenRevokedError,
    UserInactiveError,
    UserNotFoundError,
)
from utils.logging import logger

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/login/")


async def get_tokens_by_cookie(request: Request) -> Dict[str, str]:
    """
    Извлекает токены из cookies запроса.

    :param request: Объект Request FastAPI для установки куки
    :return: Словарь с токенами ('access_token', 'refresh_token') или вызывает исключение, если токены отсутствуют
    """
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")

    if access_token and refresh_token:
        logger.debug("Токены успешно извлечены из cookies.")
        return {"access_token": access_token, "refresh_token": refresh_token}

    logger.warning("Отсутствуют необходимые cookie с токенами.")
    raise CookieMissingTokenError()


def clear_cookie_with_tokens(response: Response) -> Response:
    """
    Очищает куки с токенами из ответа.

    :param response: Объект Response FastAPI для установки куки
    :return: Модифицированный ответ
    """
    response.delete_cookie(ACCESS_TOKEN_TYPE)
    response.delete_cookie(REFRESH_TOKEN_TYPE)
    return response


def set_tokens_cookie(key: str, value: str, max_age: int, response: Response):
    """
    Устанавливает токен в куки с настройками безопасности.

    :param key: Имя ключа (обычно 'access_token' или 'refresh_token')
    :param value: Значение токена
    :param max_age: Срок жизни токена в секундах
    :param response: Объект Response FastAPI для установки куки
    :raise SetCookieFailedError: Если установка куки прошла неудачно
    """
    try:
        response.set_cookie(
            key=key,
            value=value,
            httponly=True,           # Доступно только через HTTP
            secure=True,             # Используется только по HTTPS
            samesite="strict",       # Предотвращение межсайтового отслеживания
            max_age=max_age,         # Продолжительность жизни токена
        )
        logger.info(
            f"Куки успешно установлены: {key}: {value[:5]}... ({max_age} секунд)")
    except Exception as exc:
        logger.error(f"Ошибка установки куки: {exc}")
        raise SetCookieFailedError() from exc


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    redis: Redis = Depends(get_redis_client),
) -> dict:
    """
    Возвращает текущего активного пользователя на основании JWT-токена.

    :param token: JWT-токен
    :param redis: Клиент Redis для хранения черных списков
    :raises InvalidTokenError: Если токен недействителен
    :raises TokenRevokedError: Если токен аннулирован
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
            raise TokenRevokedError()

        # Запрашиваем пользователя из базы данных
        user = await UsersRepo.select_user_by_user_id(user_id)

        # Проверяем полученного user'а
        if not user:
            raise UserNotFoundError()

        return {
            'jti': jti,
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'is_active': user.is_active,
            'iat': iat
        }

    except PyJWTError as err:
        logger.error(f"Ошибка декодирования токена: {err}")
        raise InvalidTokenError()


async def get_current_active_user(current_user: dict = Depends(get_current_user)):
    """
    Возвращает активного пользователя.

    :param current_user: Пользователь из зависимости get_current_user
    :raises UserInactiveError: Если пользователь неактивен
    :return: Активный пользователь
    """
    if current_user['is_active'] == True:
        return current_user
    raise UserInactiveError()
