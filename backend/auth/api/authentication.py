import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from typing import Annotated
from fastapi import APIRouter, Depends, Request, Response
from fastapi.security import OAuth2PasswordRequestForm

from core.schemas.users import (
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
)
from services.auth_service import (
    AuthService,
)
from deps.auth_deps import (
    get_current_active_user,
)
from exceptions.exceptions import (
    InvalidCredentialsError,
    PasswordRequiredError,
    RefreshUserTokensFailedError,
    RegistrationFailedError,
    UserAlreadyExistsError,
)

from utils.logging import logger
from utils.time_decorator import async_timed_report
from utils.security import ACCESS_TOKEN_TYPE, decode_access_token

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
async def auth_register_user(
    request: Request, response: Response, register_request: RegisterRequest
):
    try:
        auth_service = AuthService()

        # 1. Проверка на текущего пользователя
        current_user_token = request.cookies.get(ACCESS_TOKEN_TYPE)
        if current_user_token:
            try:
                payload = decode_access_token(current_user_token)

                # Извлечение данных из токена
                access_jti: str | None = payload.get("jti")
                sub: int | None = payload.get("sub")

                if access_jti and sub:
                    user_id = int(sub)
                    logger.info(
                        f"Авто-выход пользователя {user_id} перед новой регистрацией"
                    )

                    await auth_service.loggout_user_logic(
                        response=response, access_jti=access_jti, user_id=user_id
                    )
            except (ValueError, TypeError, Exception) as e:
                logger.warning(f"Не удалось выполнить авто-выход: {e}")
                pass

        # 2. Регистрируем нового пользователя
        # Подготовленные данные пользователя без пароля (пароль хешируется отдельно)
        payload = {
            "username": register_request.username,
            "email": register_request.email,
            "profile": register_request.profile,
        }
        new_user = await auth_service.register_user_to_db(
            payload=payload, password=register_request.password
        )

        return {"message": f"Регистрация пользователя: {new_user!r} прошла успешно!"}

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
    user=Depends(get_current_active_user),
):
    auth_service = AuthService()
    access_jti = user["access_jti"]
    user_id = user["user_id"]
    await auth_service.loggout_user_logic(
        response=response, access_jti=access_jti, user_id=user_id
    )
    return {"detail": "Выход выполнен успешно"}


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
