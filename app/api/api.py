from fastapi import APIRouter

from api import autorization, employees

router = APIRouter()
router.include_router(autorization.router, tags=["Authentication"], prefix="/users")
router.include_router(employees.router, tags=["Employees"], prefix="/employees")
