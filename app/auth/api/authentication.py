from fastapi import APIRouter, Depends, Form, Response

from db.users_repository import UsersRepo
from config import settings
from app_redis.client import get_redis_client
from utils.security import create_access_token, create_refresh_token
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
    SessionDep,
    get_current_token_payload,
    get_current_user,
    http_bearer,
    oauth2_scheme,
)

from utils.logging import logger

# TODO fix unauthorized errors (based on invalid types)
# INFO:     127.0.0.1:53955 - "POST /users/login/ HTTP/1.1" 200 OK
# INFO:     127.0.0.1:53955 - "POST /users/logout/ HTTP/1.1" 401 Unauthorized
# INFO:     127.0.0.1:53955 - "POST /users/refresh/ HTTP/1.1" 401 Unauthorized
# INFO:     127.0.0.1:53958 - "GET /users/me/ HTTP/1.1" 401 Unauthorized

auth = APIRouter(
    dependencies=[Depends(http_bearer)],
)
auth_usage = APIRouter()
dev_usage = APIRouter()


# TODO refresh_hash insert db
@auth.post('/login/')
async def login(response: Response, request: LoginRequest):
    logger.info(f'Принял логин: {request.login!r} и пароль: {request.password!r} ')
    if not request.password:
        raise PasswordRequiredError()
    user = await authenticate_user(response, request.login, request.password)
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


# @auth.post("/logout/")
# async def logout_user(
#     redis=Depends(get_redis_client),
#     user=Depends(get_current_user),
# ) -> Response:
#     try:
#         # TODO Удаляем куки токенов
#         response = Response(
#             content={'message': 'logout succesfully'},
#             status_code=200,
#             media_type="application/json",
#         )  
#         access_jti = user["jti"]  # ← можно извлечь из JWT
#         user_id = user["user_id"]

#         # 1. Черный список access
#         ttl = settings.jwt.access_token_expire_minutes * 60
#         await redis.setex(f"blacklist:access:{access_jti}", ttl, "1")

#         # TODO 2. Инвалидировать все refresh-токены пользователя
#         # await invalidate_all_refresh_tokens(user_id)

#         return response
#     except Exception as ex:
#         logger.error(f'logout user failed: {ex}')
#         raise LogoutUserFailedError()


@auth_usage.get('/me/')
async def auth_user_check_self_info(
    payload: dict = Depends(get_current_token_payload),
    current_user: dict = Depends(get_current_user),
):
    user = await UsersRepo.select_user_by_user_id(current_user['user_id'])
    if user:
        iat = payload.get('iat')
        return {
            'username': user.username,
            'email': user.email,
            'logged_in_at': iat,
        }
    raise UserNotFoundError()
