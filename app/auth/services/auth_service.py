from typing import Any

from schemas.users import UserInDB

from services.jwt_tokens import (
    create_access_token,
    create_refresh_token,
    )

from exceptions.exceptions import (
    InvalidCredentialsError,
    InvalidPasswordError,
    PasswordRequiredError,
    UserNotFoundError,
    UserInactiveError,
    )

from utils.security import check_password
from db.user_repository import UsersRepo


async def authenticate_user(
    username: str,
    password: str,
) -> dict[str, Any]:
    user_data_from_db = await UsersRepo.select_user_by_username(username)

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
    user_id = user_data_from_db.id
    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)

    return {
        "user_id": user_id,
        "access_token": access_token,
        "refresh_token": refresh_token,
    }

# TODO: Сделать функцию для регистрации 
# async def register_user(
#     payload: dict,
#     password: str,
# ) -> ...:
    