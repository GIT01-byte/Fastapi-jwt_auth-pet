from datetime import datetime, timedelta, timezone
from fastapi import Response

from core.db.repositories import UsersRepo, RefreshTokensRepo
from core.models.users import User
from core.schemas.users import TokenResponse, UserRead
from core.app_redis.client import get_redis_client
from exceptions.exceptions import (
    RedisConnectionError,
    RefreshTokenExpiredError,
    RefreshTokenNotFoundError,
    RevokeTokenFailedError,
    InvalidPasswordError,
    UserAlreadyExistsError,
    UserInactiveError,
    UserNotFoundError,
    RegistrationFailedError,
)
from utils.security import (
    check_password,
    create_access_token,
    create_refresh_token as gen_refresh_token,
    hash_password,
    hash_token,
)
from deps.auth_deps import (
    clear_cookie_with_tokens,
    set_tokens_cookie,
)

from core.settings import settings
from utils.logging import logger

# TODO Вынести в общий класс и отрефакторить код по принципу DRY
class AuthService():
    async def _get_user_for_login(self, login: str) -> User:
        """
        Docstring для _get_user_from_db
        
        :param self: Описание
        :param login: Описание
        :type login: str
        :return: Описание
        :rtype: User
        """
        # Получение пользователя из БД
        user = await UsersRepo.select_user_by_username(login)

        # Проверка на нахождение
        if not user:
            logger.warning(f"Пользователь с логином {login!r} не найден в базе данных.")
            raise UserNotFoundError()
        logger.debug(f"Пользователь {login!r} найден в БД (ID: {user.id}).")

        # Проверка на активность
        if not user.is_active:
            logger.warning(f"Пользователь {login!r} неактивен.")
            raise UserInactiveError()
        logger.debug(f"Пользователь {login!r} активен.")
        return user

    async def _get_user_for_token(self, user_id: int):
        """
        Docstring для _get_user_from_db
        
        :param self: Описание
        :param login: Описание
        :type login: str
        :return: Описание
        :rtype: User
        """
        # Получение пользователя из БД
        user = await UsersRepo.select_user_by_user_id(user_id)

        # Проверка на нахождение
        if not user:
            logger.warning(f"Пользователь (ID: {user_id}) не найден в базе данных.")
            raise UserNotFoundError()
        logger.debug(f"Пользователь (ID: {user.id}) найден в БД .")

        # Проверка на активность
        if not user.is_active:
            logger.warning(f"Пользователь (ID: {user.id}) неактивен.")
            raise UserInactiveError()
        logger.debug(f"Пользователь (ID: {user.id}) активен.")
        return user

    async def _get_vaild_token(self, raw_token: str):
        """
        Docstring для _get_vaild_token
        
        :param self: Описание
        :param raw_token: Описание
        :type raw_token: str
        :return: Описание
        :rtype: Any
        """
        token_hash = hash_token(raw_token)
        stored = await RefreshTokensRepo.get_refresh_token(token_hash)
        if not stored or stored.revoked:
            raise RefreshTokenNotFoundError()
        now = datetime.now(timezone.utc)
        if stored.expires_at <= now:
            await RefreshTokensRepo.delete_refresh_token(stored)
            raise RefreshTokenExpiredError()
        return stored

    async def _issue_tokens(self, user_id: int) -> tuple[str, str]:
        """
        Docstring для _issue_tokens
        
        :param self: Описание
        :param user_id: Описание
        :type user_id: int
        :return: Описание
        :rtype: Any
        """
        # Генерация токенов
        access_token = create_access_token(user_id)
        refresh_token, refresh_hash = gen_refresh_token()
        logger.debug(f"Access и Refresh токены сгенерированы для пользователя ID: {user_id}.")

        # Сохранение Refresh токена в БД
        expires_at = datetime.now(
        timezone.utc) + timedelta(minutes=settings.jwt.refresh_token_expire_days)
        await RefreshTokensRepo.create_refresh_token(user_id, refresh_hash, expires_at)
        logger.info(f"Refresh токен сохранен в БД для пользователя ID: {user_id}.")

        return access_token, refresh_token

    async def authenticate_user(self, response: Response, login: str, password: str) -> TokenResponse:
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
            # 1. Получение пользоваетеля из БД и проверка на активность
            user_data_from_db = await self._get_user_for_login(login=login)

            # 2. Проверка пароля
            if not check_password(
                password=password,
                hashed_password=user_data_from_db.hashed_password
            ):
                logger.warning(f"Неверный пароль для пользователя {login!r}.")
                raise InvalidPasswordError()
            logger.debug(f"Пароль для пользователя {login!r} верен.")

            # 3. Преобразование данных пользователя в Pydantic модель
            user = UserRead(
                id=user_data_from_db.id,
                username=user_data_from_db.username,
                email=user_data_from_db.email,
                is_active=user_data_from_db.is_active,
            )
            logger.debug(f"Данные пользователя {login!r} успешно преобразованы в Pydantic модель.")

            # 4. Генерация токенов и сохранение Refresh токена в БД
            user_id = user.id
            access_token, refresh_token = await self._issue_tokens(user_id=user_id)
            
            # 5. Установка токенов в куки
            set_tokens_cookie(response=response, access_token=access_token, refresh_token=refresh_token)
            logger.info(f"Куки с токенами установлены для пользователя ID: {user.id}.")
        
            logger.info(f"Пользователь {user.username!r} успешно аутентифицирован.")
            return TokenResponse(
                access_token=access_token,
                refresh_token=refresh_token,
            )
        
        except (UserNotFoundError, InvalidPasswordError, UserInactiveError) as e:
            raise e
        except Exception as e:
            logger.exception(
                f"Неожиданная ошибка при аутентификации пользователя {login!r}: {e}")
            raise RegistrationFailedError() from e

    async def register_user_to_db(self, payload: dict, password: str) -> str:
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
        logger.info(
            f"Начало регистрации нового пользователя: username={username!r}, email={email!r}.")
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
                logger.info(
                    f"Пользователь {new_username!r} успешно зарегистрирован с ID: {created_user_in_db.id}.")
                return new_username
            else:
                logger.error(
                    f"UsersRepo.create_user вернул None для пользователя {username!r} без исключения.")
                raise RegistrationFailedError(
                    "User registration failed unexpectedly: no user returned.")

        except UserAlreadyExistsError as e:
            raise e
        except Exception as e:
            logger.exception(
                f"Неожиданная ошибка при регистрации пользователя {username!r}: {e}")
            raise RegistrationFailedError(
                f"Internal error during registration: {e}") from e

    async def revoke_token(self, jti: str, expire: int):
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

    async def refresh(self, response: Response, raw_token: str):
        stored = await self._get_vaild_token(raw_token)
        user = await self._get_user_for_token(stored.user_id)
        await RefreshTokensRepo.delete_refresh_token(stored)

        # Генерация токенов и сохранение Refresh токена в БД
        user_id = user.id
        access_token, refresh_token = await self._issue_tokens(user_id=user_id)

        # Установка токенов в куки
        clear_cookie_with_tokens(response=response)
        set_tokens_cookie(response=response, access_token=access_token, refresh_token=refresh_token)
        logger.info(f"Куки с токенами установлены для пользователя ID: {user.id}.")

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
        )
