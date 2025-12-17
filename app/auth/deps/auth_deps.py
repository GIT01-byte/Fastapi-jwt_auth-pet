from typing import Any, Callable, Coroutine

from fastapi.security import HTTPBearer, OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError as JWTInvalidTokenError

from fastapi import Depends, Form, Request, Response

from app_redis.client import get_redis_client
from exceptions.exceptions import (
    CookieMissingTokenError,
    InvalidCredentialsError,
    InvalidTokenError,
    InvalidTokenPayload,
    SetCookieFailedError,
    TokenRevokedError,
    UserInactiveError,
    ValidateAuthUserFailedError,
)
from schemas.users import UserInDB
from utils.security import (
    TOKEN_TYPE_FIELD,
    check_password,
    REFRESH_TOKEN_TYPE,
    ACCESS_TOKEN_TYPE,
    decode_jwt,
)
from db.user_repository import UsersRepo

from utils.logging import logger


http_bearer = HTTPBearer(auto_error=False)

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl='/users/login/'
)


# async def validate_auth_user(
#     username: str = Form(),
#     password: str = Form(),
# ) -> UserInDB:
#     """
#     Валидирует учетные данные пользователя для входа.
#     """
#     try:
#         logger.debug(f"Получение пользователя по имени '{username}'...")
#         user_data_from_db = await UsersRepo.select_user_by_login(username)

#         if not user_data_from_db:
#             logger.warning(f"Пользователь '{username}' не найден!")
#             raise InvalidCredentialsError(
#                 detail='invalid username or password')

#         logger.debug(f"Полученный пользователь: {user_data_from_db}")

#         if not check_password(password=password, hashed_password=user_data_from_db.hashed_password):
#             logger.warning(f"Неверный пароль для пользователя '{username}'")
#             raise InvalidCredentialsError(
#                 detail='invalid username or password')

#         if not user_data_from_db.is_active:
#             logger.info(f"Пользователь '{username}' неактивен.")
#             raise UserInactiveError()

#         logger.debug(f"Возвращаю данные пользователя: {user_data_from_db}")
#         return UserInDB(
#             id=user_data_from_db.id,
#             username=user_data_from_db.username,
#             email=user_data_from_db.email,
#             hashed_password=user_data_from_db.hashed_password,
#             is_active=user_data_from_db.is_active,
#         )
#     except Exception as ex:
#         logger.error(f"Ошибка при проверке учетных данных пользователя: {ex}")
#         raise ValidateAuthUserFailedError()


def get_current_token_payload(token: str = Depends(oauth2_scheme)) -> dict[str, Any]:
    """
    Декодирует JWT-токен и возвращает его полезную нагрузку.
    """
    try:
        logger.debug(f'Начинаю декодировать токен: {token}')
        payload: dict[str, Any] = decode_jwt(token=token)
        logger.debug(f"Декодированный токен: {payload}")
        return payload
    except JWTInvalidTokenError as ex:
        logger.error(f"Ошибка декодирования токена: {ex}")
        raise InvalidTokenError(detail='invalid token')


# def validate_token_type(
#     payload: dict[str, Any],
#     token_type: str,
# ) -> bool:
#     """
#     Проверяет тип токена в полезной нагрузке.
#     """
#     current_token_type = payload.get(TOKEN_TYPE_FIELD)
#     if current_token_type == token_type:
#         logger.debug(f"Тип токена подтвержден: {token_type}.")
#         return True
#     else:
#         logger.error(
#             f"Тип токена неверен: ожидается '{token_type}', получен '{current_token_type}'.")
#         raise InvalidTokenError()


# async def get_user_by_token_sub(
#     payload: dict[str, Any]
# ) -> UserInDB:
#     """
#     Извлекает пользователя из базы данных по 'sub' (user_id) из полезной нагрузки токена.
#     """
#     user_id = payload.get('sub')
#     if user_id:
#         logger.debug(f"Ищу пользователя с ID={user_id}...")
#         user_data_from_db = await UsersRepo.select_user_by_user_id(int(user_id))
#         if not user_data_from_db:
#             logger.warning(f"Пользователь с ID={user_id} не найден!")
#             raise InvalidCredentialsError(
#                 detail='invalid username or password')
#         logger.debug(f"Найденный пользователь: {user_data_from_db}")
#         return UserInDB(
#             id=user_data_from_db.id,
#             username=user_data_from_db.username,
#             email=user_data_from_db.email,
#             hashed_password=user_data_from_db.hashed_password,
#             is_active=user_data_from_db.is_active,
#         )
#     else:
#         logger.error("Нет поля 'sub' в токене.")
#         raise InvalidTokenPayload()

# Фабричная функция для создания зависимостей, проверяющих тип токена


# def get_auth_user_from_token_of_type(token_type: str) -> Callable[[dict[str, Any]], Coroutine[Any, Any, UserInDB]]:
#     """
#     Фабрика зависимостей, которая возвращает асинхронную функцию для получения
#     аутентифицированного пользователя определенного типа токена.
#     """
#     async def get_auth_user_from_token(
#         payload: dict[str, Any] = Depends(get_current_token_payload)
#     ) -> UserInDB:
#         logger.debug(f"Валидация токена типа '{token_type}'...")
#         validate_token_type(payload, token_type)
#         return await get_user_by_token_sub(payload)
#     return get_auth_user_from_token


# # Создаем конкретные зависимости, используя фабрику
# get_current_auth_user = get_auth_user_from_token_of_type(ACCESS_TOKEN_TYPE)
# get_current_auth_user_for_refresh = get_auth_user_from_token_of_type(
#     REFRESH_TOKEN_TYPE)


# async def get_current_active_auth_user(
#     user: UserInDB = Depends(get_current_auth_user)
# ) -> UserInDB:
#     """
#     Возвращает текущего активного аутентифицированного пользователя.
#     """
#     logger.info(f"Авторизация пользователя: {user.id=}, {user.username=}")
#     if user.is_active:
#         return user
#     raise UserInactiveError()


def get_tokens_by_cookie(request: Request) -> dict[str, str]:
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")
    
    if access_token and refresh_token:
        logger.debug("Токены успешно извлечены из cookies.")
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
        }
    
    logger.warning("Отсутствуют необходимые cookie с токенами.")
    raise CookieMissingTokenError()

def clear_cookie_with_tokens(response: Response) -> Response:
    response.delete_cookie(ACCESS_TOKEN_TYPE)
    response.delete_cookie(REFRESH_TOKEN_TYPE)

    return response

def set_tokens_cookie(
    key: str,
    value: str,
    max_age: int,
    response: Response,
):
    # Устанавливаем куки, включая настройки безопасности
    try:
        response.set_cookie(
            key=key,
            value=value,
            httponly=True,          # Доступно только через HTTP
            secure=True,            # Только по HTTPS (важно для безопастности)
            samesite="lax",         # Защита от CSRF
            max_age=max_age * 60 if isinstance(max_age, int) else None, 
        )
        logger.info(f'Установка куки успешно произошла. Ключ: {key!r}, значение: {value!r}, время жизни: {max_age!r} минут')
    except:
        logger.error(f'Установка куки произошла с ошибкой. Ключ: {key!r}, значение: {value!r}, время жизни: {max_age!r} минут')
        raise SetCookieFailedError()

# TODO update auth deps
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    redis = Depends(get_redis_client),
) -> dict:
    """
    Извлекает и валидирует JWT access-токен.
    Возвращает словарь: {"user_id": str, "jti": str}
    """
    try:
        payload = get_current_token_payload(token)

        user_id: str | None = payload.get("sub")
        jti: str | None = payload.get("jti")
        token_type: str | None = payload.get("type")

        if not user_id or not jti:
            raise InvalidTokenError("Missing required claims: sub or jti")

        if token_type != "access":
            raise InvalidTokenError("Invalid token type: expected 'access'")

        # Проверка чёрного списка Redis
        if await redis.exists(f"blacklist:access:{jti}"):
            raise TokenRevokedError()

        return {"user_id": user_id, "jti": jti}

    except JWTInvalidTokenError:
        raise InvalidTokenError()
