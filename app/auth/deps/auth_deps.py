from jwt import InvalidTokenError

from fastapi import (
    Depends, 
    Form, 
    HTTPException,
    Request,
    status,
)

from fastapi.security import (
    HTTPBearer,
    OAuth2PasswordBearer,
)

from models.users import UsersOrm

from exceptions.exceptions import (
    CookieMissingTokenError,
    InvalidCredentialsError,
    MalformedTokenError, 
    InvalidTokenPayload,
    UserInactiveError,
)

from schemas.users import UserInDB

from utils.security import (
    check_password, 
    decode_jwt,
)

from db.user_repository import UsersRepo

from services.jwt_tokens import (
    TOKEN_TYPE_FIELD,
    ACCESS_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
)

from typing import Any, Callable, Coroutine 

import logging


logger: logging.Logger = logging.getLogger(__name__)


http_bearer = HTTPBearer(auto_error=False)


async def validate_auth_user(
    username: str = Form(),
    password: str = Form(),
) -> UserInDB:
    """
    Валидирует учетные данные пользователя для входа.
    """
    user_data_from_db = await UsersRepo.select_user_by_username(username)
    
    if not user_data_from_db:
        raise InvalidCredentialsError(detail='invalid username or password')
    
    if not check_password(
        password=password,
        hashed_password=user_data_from_db.hashed_password,
    ):
        raise InvalidCredentialsError(detail='invalid username or password')
    
    if not user_data_from_db.is_active:
        raise UserInactiveError()
    
    # Преобразуем данные из репозитория в Pydantic модель
    return UserInDB(
        id=user_data_from_db.id,
        username=user_data_from_db.username,
        email=user_data_from_db.email,
        hashed_password=user_data_from_db.hashed_password,
        is_active=user_data_from_db.is_active,
    )


def get_tokens_by_cookie(request: Request) -> dict[str, str]:
    access_token: str | None = request.cookies.get("access_token")
    refresh_token: str | None = request.cookies.get("refresh_token")
    
    if access_token and refresh_token:
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
        }
    
    raise CookieMissingTokenError()


def get_current_token_payload(
    tokens: dict[str, str] = Depends(get_tokens_by_cookie),
) -> dict[str, Any]:
    """
    Декодирует JWT-токен и возвращает его полезную нагрузку.
    """
    try:
        payload: dict[str, Any] = decode_jwt(
            token=tokens['access_token'],
        )
    except InvalidTokenError as e:
        # TODO: Добавить логирование
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f'invalid token error: {e}'
        )
    return payload


def validate_token_type(
    payload: dict[str, Any],
    token_type: str,
) -> bool:
    """
    Проверяет тип токена в полезной нагрузке.
    """
    current_token_type: Any | None = payload.get(TOKEN_TYPE_FIELD)
    if current_token_type == token_type:
        return True
    raise MalformedTokenError()


async def get_user_by_token_sub(
    payload: dict[str, Any]
) -> UserInDB:
    """
    Извлекает пользователя из базы данных по 'sub' (user_id) из полезной нагрузки токена.
    """
    user_id: int | None = int(payload.get('sub')) # type: ignore
    if user_id:
        user_data_from_db: UsersOrm | None = await UsersRepo.select_user_by_user_id(user_id)
        if not user_data_from_db:
            raise InvalidCredentialsError(detail='invalid username or password') 
        return UserInDB(
            id=user_data_from_db.id,
            username=user_data_from_db.username,
            email=user_data_from_db.email,
            hashed_password=user_data_from_db.hashed_password,
            is_active=user_data_from_db.is_active,
        )
    raise InvalidTokenPayload()


# Фабричная функция для создания зависимостей, проверяющих тип токена
# Возвращаемый тип фабрики: Callable, который возвращает Coroutine, который, в свою очередь, возвращает UserInDB
def get_auth_user_from_token_of_type(token_type: str) -> Callable[[dict[str, Any]], Coroutine[Any, Any, UserInDB]]:
    """
    Фабрика зависимостей, которая возвращает асинхронную функцию для получения
    аутентифицированного пользователя определенного типа токена.
    """
    async def get_auth_user_from_token(
        payload: dict[str, Any] = Depends(get_current_token_payload) # Уточнен тип payload
    ) -> UserInDB: # <-- Внутренняя функция возвращает UserInDB после выполнения
        validate_token_type(payload, token_type)
        return await get_user_by_token_sub(payload)
    return get_auth_user_from_token


# Создаем конкретные зависимости, используя фабрику
get_current_auth_user: Callable[[dict[str, Any]], Coroutine[Any, Any, UserInDB]] = get_auth_user_from_token_of_type(ACCESS_TOKEN_TYPE)

get_current_auth_user_for_refresh: Callable[[dict[str, Any]], Coroutine[Any, Any, UserInDB]] = get_auth_user_from_token_of_type(REFRESH_TOKEN_TYPE)


async def get_current_active_auth_user(
    user: UserInDB = Depends(get_current_auth_user)
) -> UserInDB:
    """
    Возвращает текущего активного аутентифицированного пользователя.
    """
    if user.is_active:
        return user
    raise UserInactiveError()
