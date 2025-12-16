from fastapi import Response

from exceptions.exceptions import (
    LogoutUserFailedError,
    UserAlreadyExistsError,
)
from utils.security import (
    hash_password,
    REFRESH_TOKEN_TYPE,
    ACCESS_TOKEN_TYPE,
)
from db.user_repository import UsersRepo

from utils.logging import logger


async def register_user_to_db(payload: dict, password: str) -> str:  # FIXME exc db
    # Хешируем пароль и добавляем в payload
    hashed_password = hash_password(password)
    full_payload = {**payload, 'hashed_password': hashed_password}

    # Добавляем пользователя в бд
    created_user_in_db = await UsersRepo.insert_user(full_payload)

    if created_user_in_db:
        new_username = created_user_in_db.username
        return new_username
    raise UserAlreadyExistsError()

# TODO fix to redis blacklist
def logout_user() -> Response:
    try:
        # Удаляем куки токенов
        response = Response(
            content='logout succesfully',
            status_code=200,
            media_type='text/'
        )
        response.delete_cookie(ACCESS_TOKEN_TYPE)
        response.delete_cookie(REFRESH_TOKEN_TYPE)
        return response
    except Exception as ex:
        logger.error(f'logout user failed: {ex}')
        raise LogoutUserFailedError()
