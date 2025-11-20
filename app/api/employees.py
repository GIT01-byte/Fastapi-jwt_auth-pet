from fastapi import APIRouter, Depends

from db.repository import EmpoloyeesRepo

from api.autorization import get_current_active_auth_user

from schemas.users import UserScheme
from schemas.employees import EmpoloyeeAddScheme


router = APIRouter()


@router.get('/team/get_employees',
    summary='Получить список сотрудников',
    )
def get_employees(
    current_user: str = Depends(get_current_active_auth_user)
):
    employees = EmpoloyeesRepo.select_all()
    return {
        'message': f'Текущий пользователь: {current_user.username}', # pyright: ignore[reportAttributeAccessIssue]
        'data': employees,
    }


@router.post('/team/add_employees',
    summary='Добавить сотрудника в список сотрудников',
    )
def add_employee(
    new_employee: EmpoloyeeAddScheme,
    current_user: str = Depends(get_current_active_auth_user),
):
    new_employee_id = EmpoloyeesRepo.insert_empoloyee(new_employee)
    return {
        'message': f'Текущий пользователь: {current_user.username}', # pyright: ignore[reportAttributeAccessIssue]
        'employee_id': new_employee_id,
    }


@router.post('/reg_user',
    summary='Зарегистрировать пользователя',
    )
def registr_user(user: UserScheme):
    return{
        'message': f'Добавлен пользователь: {user.username}',
    }

