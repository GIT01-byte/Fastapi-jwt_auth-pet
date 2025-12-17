from fastapi import status
from .base import BaseAPIException


class CookieMissingTokenError(BaseAPIException):
    def __init__(self, detail: str = "Missing required cookies."):
        super().__init__(detail=detail, status_code=status.HTTP_401_UNAUTHORIZED)


class InvalidCredentialsError(BaseAPIException):
    def __init__(self, detail: str = "Invalid credentials"):
        super().__init__(detail=detail, status_code=status.HTTP_401_UNAUTHORIZED)


class PasswordRequiredError(BaseAPIException):
    def __init__(self, detail: str = "Password is required"):
        super().__init__(detail=detail, status_code=status.HTTP_401_UNAUTHORIZED)


class InvalidPasswordError(BaseAPIException):
    def __init__(self, detail: str = "Password is invalid"):
        super().__init__(detail=detail, status_code=status.HTTP_401_UNAUTHORIZED)


class TokenExpiredError(BaseAPIException):
    def __init__(self, detail: str = "Token has expired"):
        super().__init__(detail=detail, status_code=status.HTTP_401_UNAUTHORIZED)


class TokenRevokedError(BaseAPIException):
    def __init__(self, detail: str = "Token has been revoked"):
        super().__init__(detail=detail, status_code=status.HTTP_401_UNAUTHORIZED)


class InvalidTokenPayload(BaseAPIException):
    def __init__(self, detail: str = "Invalid token payload"):
        super().__init__(detail=detail, status_code=status.HTTP_401_UNAUTHORIZED)


class InvalidTokenError(BaseAPIException):
    def __init__(self, detail: str = "Invalid or malformed token"):
        super().__init__(detail=detail, status_code=status.HTTP_401_UNAUTHORIZED)


class UserInactiveError(BaseAPIException):
    def __init__(self, detail: str = "User is not active"):
        super().__init__(detail=detail, status_code=status.HTTP_403_FORBIDDEN)


class UserNotFoundError(BaseAPIException):
    def __init__(self, detail: str = "User not found"):
        super().__init__(detail=detail, status_code=status.HTTP_404_NOT_FOUND)


class UserAlreadyExistsError(BaseAPIException):
    def __init__(self, detail: str = "User with this username or email already exists"):
        super().__init__(detail=detail, status_code=status.HTTP_409_CONFLICT)


class UserAlreadyLoggedgError(BaseAPIException):
    def __init__(self, detail: str = "User already logged"):
        super().__init__(detail=detail, status_code=status.HTTP_409_CONFLICT)


class RegistrationFailedError(BaseAPIException):
    def __init__(self, detail: str = "Registration failed due to internal error"):
        super().__init__(detail=detail, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SetCookieFailedError(BaseAPIException):
    def __init__(self, detail: str = "Set cookie failed due to interanl error"):
        super().__init__(detail=detail, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RefreshUserTokenFailesError(BaseAPIException):
    def __init__(self, detail: str = "Refresh user token failed due to interanl error"):
        super().__init__(detail=detail, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutUserFailedError(BaseAPIException):
    def __init__(self, detail: str = "logout user failed due to interanl error"):
        super().__init__(detail=detail, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ValidateAuthUserFailedError(BaseAPIException):
    def __init__(self, detail: str = "validate auth user failed due to interanl error"):
        super().__init__(detail=detail, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
