import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from typing import Annotated
from fastapi import APIRouter, Depends, Response
from fastapi.security import OAuth2PasswordRequestForm

from core.app_redis.client import get_redis_client
from core.db.repositories import RefreshTokensRepo
from core.schemas.users import (
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
)
from services.auth_service import (
    AuthService,
)
from deps.auth_deps import (
    clear_cookie_with_tokens,
    get_current_active_user,
)
from exceptions.exceptions import (
    InvalidCredentialsError,
    LogoutUserFailedError,
    PasswordRequiredError,
    RefreshUserTokensFailedError,
    RegistrationFailedError,
    UserAlreadyExistsError,
)

from core.settings import settings
from utils.logging import logger
from utils.time_decorator import async_timed_report, sync_timed_report

# Роутеры для аутентификации и разработки
auth = APIRouter()
auth_usage = APIRouter()
dev_usage = APIRouter()


# Вход пользователя с выдачей токенов
@auth.post("/login/", response_model=TokenResponse)
@async_timed_report()
async def auth_login(
    response: Response, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    auth_service = AuthService()
    if not form_data.password:
        raise PasswordRequiredError()

    # Авторизация пользователя
    user = await auth_service.authenticate_user(
        response, form_data.username, form_data.password
    )
    if not user:
        raise InvalidCredentialsError()

    return TokenResponse(
        access_token=user.access_token,
        refresh_token=user.refresh_token,
    )


# Регистрация нового пользователя
@auth.post("/register/")
@async_timed_report()
async def auth_register_user(request: RegisterRequest):
    try:
        auth_service = AuthService()
        # Подготовленные данные пользователя без пароля (пароль хешируется отдельно)
        payload = {
            "username": request.username,
            "email": request.email,
            "profile": request.profile,
        }
        new_user = await auth_service.register_user_to_db(
            payload=payload, password=request.password
        )

        return {"message": f"Регистрация пользователя {new_user!r} прошла успешно!"}

    # Обрабатываем уникальные ошибки регистрации
    except ValueError as e:
        err_msg = str(e)
        if "уже существует" in err_msg:
            raise UserAlreadyExistsError()
        logger.error(f'Ошибка регистрации, exc_info="{err_msg}"')
        raise RegistrationFailedError(detail=err_msg)
    except Exception as e:
        err_msg = str(e)
        if "уже существует" in err_msg:
            raise UserAlreadyExistsError()
        logger.error(f'Ошибка регистрации, exc_info="{err_msg}"')
        raise RegistrationFailedError()


# Обновление JWT-токенов
@auth.post("/tokens/refresh/", response_model=TokenResponse)
@async_timed_report()
async def auth_refresh_jwt(data: RefreshRequest, response: Response):
    try:
        auth_service = AuthService()
        # Выполняем обновление токенов
        pair = await auth_service.refresh(
            response=response, raw_token=data.refresh_token
        )
        return TokenResponse(
            access_token=pair.access_token,
            refresh_token=pair.refresh_token,
        )
    except Exception as ex:
        logger.error(f"Обновление токенов прошло неудачно: {ex}")
        raise RefreshUserTokensFailedError()


# Выход пользователя (разлогинивание)
@auth.post("/logout/")
@async_timed_report()
async def auth_logout_user(
    response: Response,
    redis=Depends(get_redis_client),
    user=Depends(get_current_active_user),
):
    try:
        # Идентификаторы токенов пользователя
        access_jti = user["jti"]
        user_id = user["user_id"]

        # Очищаем куки с токенами
        clear_cookie_with_tokens(response)

        # Помещаем Access-токен в черный список Redis
        ttl = settings.jwt.access_token_expire_minutes * 60
        await redis.setex(f"blacklist:access:{access_jti}", ttl, "1")

        # Инвалидация всех Refresh-токенов пользователя
        await RefreshTokensRepo.invalidate_all_refresh_tokens(user_id)

        return {"detail": "Выход выполнен успешно"}
    except Exception as ex:
        logger.error(f"Ошибка выхода пользователя: {ex}")
        raise LogoutUserFailedError()


# Получение информации о себе (авторизованном пользователе)
@auth_usage.get("/me/")
@async_timed_report()
async def auth_user_check_self_info(
    current_user: dict = Depends(get_current_active_user),
):
    return {
        "username": current_user["username"],
        "email": current_user["email"],
        "logged_in_at": current_user["iat"],  # Время входа
    }
