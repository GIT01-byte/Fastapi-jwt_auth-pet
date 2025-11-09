from typing import Annotated
from fastapi import APIRouter, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials


router = APIRouter(
    prefix='/test_task/v1',
)

security = HTTPBasic()


@router.get('/auth/',
    summary='Пройти аунтефикацию',
    tags=['Auth'],
)
def basic_auth_credentials(
    credentials: Annotated[HTTPBasicCredentials, Depends(security)],
):
    return {
        'message': 'Auth is success!',
        'username': credentials.username,
        'password': credentials.password,
    }


@router.get('/team/get_employees/',
    summary='Получить список сотрудников',
    tags=['Employees'],
)
def get_employees():
    pass
