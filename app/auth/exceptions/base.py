from fastapi import HTTPException, status


class BaseAPIException(HTTPException):
    """Базовое исключение для всех кастомных ошибок API"""

    def __init__(self, detail: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        super().__init__(status_code=status_code, detail=detail)


class RepositoryError(HTTPException):
    """Базовое исключение для операций репозитория."""

    def __init__(self, detail: str, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR):
        super().__init__(status_code=status_code, detail=detail)
