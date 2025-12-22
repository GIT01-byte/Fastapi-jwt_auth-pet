from datetime import datetime, timedelta, timezone
from fastapi import Depends, Response

from db.users_repository import UsersRepo, RefreshTokensRepo
from config import settings
from schemas.users import UserInDB
from app_redis.client import get_redis_client
from exceptions.exceptions import (
    RedisConnectionError,
    RevokeTokenFailedError,
    InvalidPasswordError,
    UserAlreadyExistsError,
    UserInactiveError,
    UserNotFoundError,
    RegistrationFailedError,
)
from utils.security import (
    ACCESS_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
    check_password,
    create_access_token,
    create_refresh_token as gen_refresh_token,
    hash_password,
)
from deps.auth_deps import (
    oauth2_scheme,
    set_tokens_cookie,
)

from utils.logging import logger


async def authenticate_user(
    response: Response,
    login: str,
    password: str,
) -> dict:
    """
    Аутентифицирует пользователя, проверяя учетные данные и активность
    Если аутентификация успешна, генерирует токены (access и refresh)
    вставляет hash refresh в БД и устанавливает их в HTTP-куки

    Args:
        response: Объект Response FastAPI для установки куки
        login: Логин пользователя (username)
        password: Пароль пользователя

    Returns:
        Словарь с информацией о пользователе и сгенерированными токенами

    Raises:
        UserNotFoundError: Если пользователь с указанным логином не найден
        InvalidPasswordError: Если предоставленный пароль неверен
        UserInactiveError: Если пользователь неактивен
        RepositoryInternalError: Если произошла внутренняя ошибка сервера
                                во время операций с БД или Redis
    """
    logger.info(f"Начало аутентификации для пользователя: {login!r}")
    try:
        # 1. Получение пользователя из БД по логину
        user_data_from_db = await UsersRepo.select_user_by_username(login)
        if not user_data_from_db:
            logger.warning(f"Пользователь с логином {login!r} не найден в базе данных.")
            raise UserNotFoundError()
        logger.debug(f"Пользователь {login!r} найден в БД (ID: {user_data_from_db.id}).")

        # 2. Проверка пароля
        if not check_password(
            password=password,
            hashed_password=user_data_from_db.hashed_password
        ):
            logger.warning(f"Неверный пароль для пользователя {login!r}.")
            raise InvalidPasswordError()
        logger.debug(f"Пароль для пользователя {login!r} верен.")

        # 3. Проверка активности пользователя
        if not user_data_from_db.is_active:
            logger.warning(f"Пользователь {login!r} неактивен.")
            raise UserInactiveError()
        logger.debug(f"Пользователь {login!r} активен.")

        # 4. Преобразование данных пользователя в Pydantic модель
        user = UserInDB(
            id=user_data_from_db.id,
            username=user_data_from_db.username,
            email=user_data_from_db.email,
            hashed_password=user_data_from_db.hashed_password,
            is_active=user_data_from_db.is_active,
        )
        logger.debug(f"Данные пользователя {login!r} успешно преобразованы в Pydantic модель.")

        # 5. Генерация токенов
        user_id = user.id
        access_token = create_access_token(user_id)
        refresh_token, refresh_hash = gen_refresh_token()
        logger.debug(f"Access и Refresh токены сгенерированы для пользователя ID: {user_id}.")

        # 6. Сохранение Refresh токена в БД
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt.refresh_token_expire_days)
        await RefreshTokensRepo.create_refresh_token(user_id, refresh_hash, expires_at)
        logger.info(f"Refresh токен сохранен в БД для пользователя ID: {user_id}.")

        # 7. Установка токенов в куки
        set_tokens_cookie(
            key=ACCESS_TOKEN_TYPE,
            value=access_token,
            max_age=settings.jwt.access_token_expire_minutes,
            response=response,
        )
        set_tokens_cookie(
            key=REFRESH_TOKEN_TYPE,
            value=refresh_token,
            max_age=settings.jwt.refresh_token_expire_days,
            response=response,
        )
        logger.info(f"Куки с токенами установлены для пользователя ID: {user_id}.")

        logger.info(f"Пользователь {user.username!r} успешно аутентифицирован.")
        return {
            "user": user.username,
            "access_token": access_token,
            "refresh_token": refresh_token,
        }
    except (UserNotFoundError, InvalidPasswordError, UserInactiveError) as e:
        raise e
    except Exception as e:
        logger.exception(f"Неожиданная ошибка при аутентификации пользователя {login!r}: {e}")
        raise RegistrationFailedError() from e


async def register_user_to_db(
    payload: dict,
    password: str,
) -> str:
    """
    Регистрирует нового пользователя в базе данных
    Хеширует пароль перед сохранением

    Args:
        payload: Словарь с данными пользователя (кроме пароля)
        password: Пароль пользователя в открытом виде

    Returns:
        Имя пользователя (username) успешно зарегистрированного пользователя

    Raises:
        UserAlreadyExistsError: Если пользователь с таким именем или email уже существует
        RegistrationFailedError: Если произошла внутренняя ошибка при регистрации
    """
    username = payload.get('username', 'N/A')
    email = payload.get('email', 'N/A')
    logger.info(f"Начало регистрации нового пользователя: username={username!r}, email={email!r}.")
    try:
        # 1. Хеширование пароля
        hashed_password = hash_password(password)
        logger.debug(f"Пароль пользователя {username!r} хеширован.")
        
        # 2. Создание полного объекта пользователя для репозитория
        full_payload = {**payload, 'hashed_password': hashed_password}

        # 3. Сохранение пользователя в БД
        created_user_in_db = await UsersRepo.create_user(full_payload)
        
        if created_user_in_db:
            new_username = created_user_in_db.username
            logger.info(f"Пользователь {new_username!r} успешно зарегистрирован с ID: {created_user_in_db.id}.")
            return new_username
        else:
            logger.error(f"UsersRepo.create_user вернул None для пользователя {username!r} без исключения.")
            raise RegistrationFailedError("User registration failed unexpectedly: no user returned.")

    except UserAlreadyExistsError as e:
        raise e
    except Exception as e:
        logger.exception(f"Неожиданная ошибка при регистрации пользователя {username!r}: {e}")
        raise RegistrationFailedError(f"Internal error during registration: {e}") from e


async def revoke_token(jti: str, expire: int):
    """
    Отзывает токен, добавляя его идентификатор (jti) в черный список Redis
    Токен считается отозванным, если его jti присутствует в Redis

    Args:
        jti: Уникальный идентификатор токена (JWT ID)
        expire: Время жизни записи в Redis в секундах (должно соответствовать
                времени жизни самого токена для надежности)
    """
    logger.debug(f"Начало отзыва токена JTI: {jti!r}.")
    try:
        # 1. Получение клиента Redis
        redis_conn = await get_redis_client()
        if redis_conn:
            logger.debug("Успешное подключение к Redis.")
            
            # 2. Добавление JTI в черный список Redis с заданным временем жизни
            await redis_conn.setex(f"revoked:{jti}", expire, "1")
            logger.info(f"Токен JTI: {jti!r} успешно отозван и добавлен в черный список Redis на {expire} секунд.")
        logger.exception("Ошибка при подключени с Redis")
        raise RedisConnectionError()
    except RedisConnectionError as e:
        raise e
    except Exception as e:
        logger.exception(f"Ошибка при отзыве токена JTI: {jti!r} в Redis: {e}")
        raise RevokeTokenFailedError("Failed to revoke token due to internal error.") from e
