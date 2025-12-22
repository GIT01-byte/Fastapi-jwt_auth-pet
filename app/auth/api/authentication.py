from typing import Annotated
from fastapi import APIRouter, Depends, Response
from fastapi.security import HTTPAuthorizationCredentials, OAuth2PasswordRequestForm

from app_redis.client import get_redis_client
from db.users_repository import RefreshTokensRepo, UsersRepo
from exceptions.exceptions import (
    InvalidCredentialsError,
    LogoutUserFailedError,
    PasswordRequiredError,
    RegistrationFailedError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from schemas.users import (
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserInDB,
)
from services.auth_service import (
    authenticate_user,
    register_user_to_db
)
from deps.auth_deps import (
    clear_cookie_with_tokens,
    get_current_active_user,
)
from utils.security import decode_access_token
from config import settings

from utils.logging import logger

# TODO fix unauthorized errors (based on invalid types)
# INFO:     127.0.0.1:53955 - "POST /users/refresh/ HTTP/1.1" 401 Unauthorized

auth = APIRouter()
auth_usage = APIRouter()
dev_usage = APIRouter()



@auth.post('/login/', response_model=TokenResponse)
async def login(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
):
    if not form_data.password:
        raise PasswordRequiredError()
    
    user = await authenticate_user(response, form_data.username, form_data.password)

    if not user:
        raise InvalidCredentialsError()
    
    return TokenResponse(
        access_token=user['access_token'],
        refresh_token=user['refresh_token'],
    )


@auth.post('/register')
async def register_user(request: RegisterRequest):
    try:
        # Подготавливаем payload без пароля (он хешируется внутри)
        payload = {
            'username': request.username,
            'email': request.email,
            'profile': request.profile,
        }
        new_user = await register_user_to_db(payload, request.password)

        return {'message': f'Register user: {new_user!r} is successfuly!'}

    # Ловим уникальность и прочие ошибки
    except ValueError as e:
        err_msg = str(e)
        if "already exists" in err_msg:
            raise UserAlreadyExistsError()
        logger.error(f'Registration error, exc_info="{err_msg}"')
        raise RegistrationFailedError(detail=err_msg)
    except Exception as e:
        err_msg = str(e)
        if "already exists" in err_msg:
            raise UserAlreadyExistsError()
        logger.error(f'Registration error, exc_info="{err_msg}"')
        raise RegistrationFailedError()


# @auth.post(
#     '/refresh/',
#     response_model=TokenResponse,
#     response_model_exclude_none=True,
# )
# def auth_refresh_jwt(
#     user: UserInDB = Depends(get_current_auth_user_for_refresh)
# ):
#     user_id = str(user.id)
#     access_token = create_access_token(user_id)
#     return TokenResponse(
#         access_token=access_token,
#     )


@auth.post("/logout/")
async def logout_user(
    response: Response,
    redis=Depends(get_redis_client),
    user=Depends(get_current_active_user),
):
    try:
        access_jti = user["jti"]
        user_id = user["user_id"]

        # Удаляем куки токенов
        clear_cookie_with_tokens(response)

        # Черный список access
        ttl = settings.jwt.access_token_expire_minutes * 60
        await redis.setex(f"blacklist:access:{access_jti}", ttl, "1")

        # Инвалидировать все refresh-токены пользователя
        await RefreshTokensRepo.invalidate_all_refresh_tokens(user_id)

        return {"detail": "Successfully logged out"}
    except Exception as ex:
        logger.error(f'logout user failed: {ex}')
        raise LogoutUserFailedError()


@auth_usage.get('/me/')
async def auth_user_check_self_info(
    current_user: dict = Depends(get_current_active_user),
):
    return {
        'username': current_user['username'],
        'email': current_user['email'],
        'logged_in_at': current_user['iat'],
    }
