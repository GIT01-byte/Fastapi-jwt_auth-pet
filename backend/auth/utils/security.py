import secrets
from typing import Any, Union
from datetime import timedelta, datetime, timezone

import jwt
import bcrypt
import hashlib

from backend.auth.exceptions.exceptions import InvalidTokenError
from backend.auth.core.settings import settings
from backend.auth.core.schemas import JWTPayload

from backend.auth.utils.logging import logger


TOKEN_TYPE_FIELD = 'type'
ACCESS_TOKEN_TYPE = 'access'
REFRESH_TOKEN_TYPE = 'refresh'


def create_access_token(user_id: int) -> str:
    """
    Создает новый access-токен для указанного пользователя.
    
    :param user_id: Идентификатор пользователя
    :return: Строка с новым access-токеном
    """
    if isinstance(user_id, int):
        jti = secrets.token_urlsafe(16)
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt.access_token_expire_minutes)
        jwt_payload = JWTPayload(
            sub=str(user_id),
            exp=expire,
            jti=jti,
        )
        logger.info(f"Создаем access-токен для пользователя с ID={user_id}, срок действия до {expire.isoformat()}")
        return encode_jwt(payload=jwt_payload)
    raise TypeError


def create_refresh_token() -> tuple[str, str]:
    """
    Генерирует новый refresh-токен и его хэшированное значение.
    
    :return: Кортеж (refresh-token, хэш refresh-токена)
    """
    token = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    logger.info(f"Создан refresh-токен для пользователя.")
    return token, token_hash


def hash_token(token: str) -> str:
    if isinstance(token, str):
        return hashlib.sha256(token.encode()).hexdigest()
    raise TypeError


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Декодирует JWT-токен и проверяет его действительность.
    
    :param token: Токен для декодирования
    :raises InvalidTokenError: Если токен недействителен
    :return: Полезная нагрузка токена
    """
    try:
        payload: dict[str, Any] = decode_jwt(token=token)
        return payload
    except jwt.PyJWTError as ex:
        logger.error(f"Ошибка декодирования токена: {ex}")
        raise InvalidTokenError(detail='invalid token')


def hash_password(password: str) -> bytes:
    """
    Хеширует пароль с использованием алгоритма bcrypt.
    
    :param password: Пароль в виде строки
    :return: Байтовые данные зашифрованного пароля
    """
    salt = bcrypt.gensalt()
    pwd_bytes: bytes = password.encode()
    hashed_pwd = bcrypt.hashpw(pwd_bytes, salt)
    logger.debug(f"Пароль успешно захеширован.")
    return hashed_pwd


def check_password(password: str, hashed_password: bytes) -> bool:
    """
    Проверяет соответствие введенного пароля хранимому хэшу.
    
    :param password: Входящий пароль
    :param hashed_password: Хэшированный пароль из базы данных
    :return: True, если пароль совпадает, иначе False
    """
    if isinstance(password, str) and isinstance(hashed_password, bytes):
        result = bcrypt.checkpw(password=password.encode(), hashed_password=hashed_password)
        logger.debug(f"Результат сравнения паролей: {'совпадает' if result else 'не совпадает'}")
        return result
    raise TypeError


def encode_jwt(
    payload: JWTPayload,
    private_key: str = settings.jwt.private_key_path.read_text(),
    algorithm: str = settings.jwt.algorithm,
    expire_minutes: int = settings.jwt.access_token_expire_minutes,
    expire_timedelta: timedelta | None = None,
) -> str:
    """
    Кодирует полезные данные в JWT-токен с указанием срока действия.
    
    :param payload: Данные для шифрования
    :param private_key: Приватный ключ RSA для подписи токена
    :param algorithm: Алгоритм шифрования
    :param expire_minutes: Время жизни токена в минутах
    :param expire_timedelta: Альтернативный временной интервал для истечения срока действия
    :return: Закодированный JWT-токен
    """
    to_encode = payload.model_dump()
    now = datetime.now(timezone.utc)
    if expire_timedelta:
        expire = now + expire_timedelta
    else:
        expire = now + timedelta(minutes=expire_minutes)
    to_encode.update(exp=expire, iat=now)
    encoded = jwt.encode(to_encode, private_key, algorithm=algorithm)
    logger.debug(f"Токен с user_id: {payload.sub} успешно закодирован.")
    return encoded


def decode_jwt(
    token: Union[str, bytes],
    public_key: str = settings.jwt.public_key_path.read_text(),
    algorithm: str = settings.jwt.algorithm,
) -> dict[str, Any]:
    """
    Декодирует JWT-токен и извлекает полезные данные.
    
    :param token: Закодированный JWT-токен
    :param public_key: Открытый ключ RSA для расшифровки
    :param algorithm: Алгоритм шифрования
    :return: Расшифрованные данные токена
    """
    if isinstance(token, (str, bytes)):
        decoded = jwt.decode(token, public_key, algorithms=[algorithm])
        logger.debug(f"Токен успешно декодирован.")
        return decoded
    raise TypeError
