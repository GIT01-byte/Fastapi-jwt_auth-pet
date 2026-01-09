import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from datetime import datetime, timedelta, timezone
from typing import NoReturn
from fastapi import Response

from core.settings import settings
from core.db.repositories import UsersRepo, RefreshTokensRepo
from core.models.users import RefreshToken, User
from core.schemas.users import TokenResponse, UserRead
from core.app_redis.client import get_redis_client
from exceptions.exceptions import (
    RedisConnectionError,
    RefreshTokenExpiredError,
    RefreshTokenNotFoundError,
    RepositoryInternalError,
    RevokeTokenFailedError,
    InvalidPasswordError,
    UserAlreadyExistsError,
    UserInactiveError,
    UserNotFoundError,
    RegistrationFailedError,
    ValidateAuthUserFailedError,
    LogoutUserFailedError,
)
from utils.security import (
    check_password,
    create_access_token,
    create_refresh_token as gen_refresh_token,
    hash_password,
    hash_token,
)
from utils.logging import logger
from utils.time_decorator import time_all_methods, async_timed_report
from deps.auth_deps import (
    clear_cookie_with_tokens,
    set_tokens_cookie,
)


@time_all_methods(async_timed_report())
class AuthService:
    async def _get_user_by_user_id(self, user_id: int) -> User:
        """
        Приватный вспомогательный метод для получения пользователя из базы данных
        по user_id с проверкой его статуса активности.

        Params:
            user_id(int): ID пользователя

        Returns:
            User: Пользователь, соответствующий переданному id.

        Raises:
            UserNotFoundError: Если пользователь с указанным логином не найден.
            UserInactiveError: Если пользователь с данным логином неактивен.
        """
        # Получение пользователя из БД
        user = await UsersRepo.select_user_by_user_id(user_id)

        # Проверка наличия пользователя
        if not user:
            logger.warning(
                f"Пользователь с логином '{user_id}' не найден в базе данных."
            )
            raise UserNotFoundError()
        else:
            logger.debug(f"Пользователь '{user_id}' найден в БД (ID: {user.id}).")

        # Проверка статуса активности пользователя
        if not user.is_active:
            logger.warning(f"Пользователь '{user_id}' неактивен.")
            raise UserInactiveError()
        else:
            logger.debug(f"Пользователь '{user_id}' активен.")

        return user

    async def _get_user_by_login(self, login: str) -> User:
        """
        Приватный вспомогательный метод для получения пользователя из базы данных
        по логину с проверкой его статуса активности.

        Args:
            login(str): Строка, содержащая логин пользователя.

        Returns:
            User: Пользователь, соответствующий переданному логину.

        Raises:
            UserNotFoundError: Если пользователь с указанным логином не найден.
            UserInactiveError: Если пользователь с данным логином неактивен.
        """
        # Получение пользователя из БД
        user = await UsersRepo.select_user_by_username(login)

        # Проверка наличия пользователя
        if not user:
            logger.warning(f"Пользователь с логином '{login}' не найден в базе данных.")
            raise UserNotFoundError()
        else:
            logger.debug(f"Пользователь '{login}' найден в БД (ID: {user.id}).")

        # Проверка статуса активности пользователя
        if not user.is_active:
            logger.warning(f"Пользователь '{login}' неактивен.")
            raise UserInactiveError()
        else:
            logger.debug(f"Пользователь '{login}' активен.")

        return user

    async def _get_valid_token(self, raw_token: str) -> RefreshToken:
        """
        Приватный вспомогательный метод для проверки валидности токена
        путем сравнения хэша с сохраненным значением.

        Params:
            raw_token(str): Строка, представляющая исходный токен.

        Returns:
            RefreshToken: Объект токена, если токен действителен и не истек срок его действия.

        Raises:
            RefreshTokenNotFoundError: если токен не найден в хранилище.
            RefreshTokenExpiredError: если токен устарел.
        """
        # Хэшируем токен
        token_hash = hash_token(raw_token)

        # Получаем токен из репозитория
        stored = await RefreshTokensRepo.get_refresh_token(token_hash)
        if not stored or stored.revoked:
            logger.error(f"Токен {raw_token[:8]}... не найден или отозван")
            raise RefreshTokenNotFoundError()
        now = datetime.now(timezone.utc)  # Текущее время UTC
        if stored.expires_at <= now:
            # Удаляем устаревший токен
            await RefreshTokensRepo.delete_refresh_token(stored)
            logger.warning(f"Устаревший токен {raw_token[:8]}... удалён")
            raise RefreshTokenExpiredError()

        logger.info(f"Токен {raw_token[:8]}... успешно проверен")
        return stored

    async def _issue_tokens(self, user_id: int) -> tuple[str, str]:
        """
        Приватный вспомогательный метод для генерации Access и Refresh токенов,
        а также для сохранения хэша Refresh токена в базе данных.

        Params:
            user_id(int): ID пользователя, для которого генерируются токены.

        Returns:
            tuple: Кортеж из Access токена (str) и "сырого" Refresh токена (str)

        Raises:
            RepositoryInternalError: Если произошла ошибка при сохранении Refresh токена в БД.
        """
        logger.debug(f"Начало генерации токенов для пользователя ID: {user_id}.")

        # 1. Генерация Access токена
        access_token = create_access_token(user_id)
        logger.debug(f"Access токен сгенерирован для пользователя ID: {user_id}.")

        # 2. Генерация Refresh токена и его хэша
        refresh_token_raw, refresh_hash = gen_refresh_token()
        logger.debug(
            f"Refresh токен (hash: {refresh_hash[:8]}...) сгенерирован для пользователя ID: {user_id}."
        )

        # 3. Сохранение Refresh токена в БД
        expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=settings.jwt.refresh_token_expire_days
        )
        logger.debug(f"Refresh токен истекает в: {expires_at.isoformat()}.")

        try:
            await RefreshTokensRepo.create_refresh_token(
                user_id, refresh_hash, expires_at
            )
            logger.info(
                f"Refresh токен (hash: {refresh_hash[:8]}...) успешно сохранен в БД для пользователя ID: {user_id}."
            )
        except Exception as e:
            logger.exception(
                f"Ошибка при сохранении Refresh токена в БД для пользователя ID: {user_id}: {e}"
            )
            raise RepositoryInternalError(
                "Failed to save refresh token to database."
            ) from e

        return access_token, refresh_token_raw

    async def authenticate_user(
        self, response: Response, login: str, password: str
    ) -> TokenResponse:
        """
        Аутентифицирует пользователя, проверяя учетные данные и активность
        Если аутентификация успешна, генерирует токены (access и refresh)
        вставляет hash refresh в БД и устанавливает их в HTTP-куки

        Params:
            response(Response): Объект Response FastAPI для установки куки
            login(str): Логин пользователя (username)
            password(str): Пароль пользователя

        Returns:
            TokenResponse: Словарь с информацией о пользователе и сгенерированными токенами

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
            user_data_from_db = await self._get_user_by_login(login=login)

            # 2. Проверка пароля
            if not check_password(
                password=password, hashed_password=user_data_from_db.hashed_password
            ):
                logger.warning(f"Неверный пароль для пользователя {login!r}.")
                raise InvalidPasswordError()
            logger.debug(f"Пароль для пользователя {login!r} верен.")

            # 3. Преобразование данных пользователя в Pydantic модель
            user = UserRead(
                id=user_data_from_db.id,
                username=user_data_from_db.username,
                email=user_data_from_db.email,  # type: ignore
                is_active=user_data_from_db.is_active,
            )
            logger.debug(
                f"Данные пользователя {login!r} успешно преобразованы в Pydantic модель."
            )

            # 4. Генерация токенов и сохранение Refresh токена в БД
            user_id = user.id
            access_token, refresh_token = await self._issue_tokens(user_id=user_id)

            # 5. Установка токенов в куки
            set_tokens_cookie(
                response=response,
                access_token=access_token,
                refresh_token=refresh_token,
            )
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
                f"Неожиданная ошибка при аутентификации пользователя {login!r}: {e}"
            )
            raise ValidateAuthUserFailedError() from e

    async def register_user_to_db(self, payload: dict, password: str) -> str:
        """
        Регистрирует нового пользователя в базе данных
        Хеширует пароль перед сохранением

        Params:
            payload(dict): Словарь с данными пользователя (кроме пароля)
            password(str): Пароль пользователя в открытом виде

        Returns:
            str: Имя пользователя (username) успешно зарегистрированного пользователя

        Raises:
            UserAlreadyExistsError: Если пользователь с таким именем или email уже существует
            RegistrationFailedError: Если произошла внутренняя ошибка при регистрации
        """
        username = payload.get("username", "N/A")
        email = payload.get("email", "N/A")
        logger.info(
            f"Начало регистрации нового пользователя: username={username!r}, email={email!r}."
        )
        try:
            # 1. Хеширование пароля
            hashed_password = hash_password(password)
            logger.debug(f"Пароль пользователя {username!r} хеширован.")

            # 2. Создание полного объекта пользователя для репозитория
            full_payload = {**payload, "hashed_password": hashed_password}

            # 3. Сохранение пользователя в БД
            created_user_in_db = await UsersRepo.create_user(full_payload)

            if created_user_in_db:
                new_username = created_user_in_db.username
                return new_username
            else:
                logger.error(
                    f"UsersRepo.create_user вернул None для пользователя {username!r} без исключения."
                )
                raise RegistrationFailedError(
                    "User registration failed unexpectedly: no user returned."
                )

        except UserAlreadyExistsError as e:
            raise e
        except Exception as e:
            logger.exception(
                f"Неожиданная ошибка при регистрации пользователя {username!r}: {e}"
            )
            raise RegistrationFailedError(
                f"Internal error during registration: {e}"
            ) from e

    async def revoke_token(self, jti: str, expire: int) -> NoReturn:
        """
        Отзывает токен, добавляя его идентификатор (jti) в черный список Redis
        Токен считается отозванным, если его jti присутствует в Redis

        Params:
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
                logger.info(
                    f"Токен JTI: {jti!r} успешно отозван и добавлен в черный список Redis на {expire} секунд."
                )

            logger.exception("Ошибка при подключени с Redis")
            raise RedisConnectionError()

        except RedisConnectionError as e:
            raise e
        except Exception as e:
            logger.exception(f"Ошибка при отзыве токена JTI: {jti!r} в Redis: {e}")
            raise RevokeTokenFailedError(
                "Failed to revoke token due to internal error."
            ) from e

    async def loggout_user_logic(self, response: Response, access_jti: str, user_id: int):
        """
        Процедура выхода текущего пользователя из системы

        Params:
            response(Response): Объект Response FastAPI 
            access_jti(str): Строка уникального индефикатора access токена 
            user_id(int): ID текущего пользвателя 
        Raises:
            LogoutUserFailedError: Если процедура выхода завершилась неудачно
        """
        try:
            # 1. Получение клиента Redis
            redis_conn = await get_redis_client()
            if redis_conn:
                logger.debug("Успешное подключение к Redis.")

            # 2. Очищаем куки с токенами
            clear_cookie_with_tokens(response)

            # 3. Помещаем Access-токен в черный список Redis
            ttl = settings.jwt.access_token_expire_minutes * 60
            await redis_conn.setex(f"blacklist:access:{access_jti}", ttl, "1")

            # 4. Инвалидация всех Refresh-токенов пользователя
            await RefreshTokensRepo.invalidate_all_refresh_tokens(user_id)

        except Exception as ex:
            logger.error(f"Ошибка выхода пользователя: {ex}")
            raise LogoutUserFailedError()

    async def refresh(self, response: Response, raw_token: str) -> TokenResponse:
        """
        Процедура обновления токенов аутентификации пользователя.

        Params:
            response(Response): Объект Response FastAPI
            raw_token(str): Строка токена

        Returns:
            TokenResponse: Объект-парой с новыми токенами

        Raises:
            RefreshTokenNotRequiredError: Если токен не найден
        """
        logger.info("Начало процедуры обновления токенов")

        # Получаем пользователя по данным из токена
        stored = await self._get_valid_token(raw_token)
        user = await self._get_user_by_user_id(stored.user_id)
        await RefreshTokensRepo.delete_refresh_token(stored)

        # Генерация новых токенов и сохранение Refresh токена в БД
        user_id = user.id
        access_token, refresh_token = await self._issue_tokens(user_id=user_id)

        # Установка токенов в куки
        set_tokens_cookie(
            response=response, access_token=access_token, refresh_token=refresh_token
        )
        logger.info(f"Куки с токенами установлены для пользователя ID: {user.id}.")

        logger.info("Процедура обновления токенов завершена успешно")
        return TokenResponse(access_token=access_token, refresh_token=refresh_token)
