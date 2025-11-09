from sqlalchemy import select

from core.database import new_session
from models.employees import EmployeesOrm


class EmpoloyeesRepo():
    @classmethod
    async def select_all(cls):
        async with new_session() as session:
            query = select(EmployeesOrm)
            result = await session.execute(query)
            task_models = result.scalars().all()
            return task_models


    @classmethod
    async def select_empoloyee_by_id(cls, empoloyee_id: int):
        async with new_session() as session:
            query = select(EmployeesOrm).where(EmployeesOrm.id == empoloyee_id)
            result = await session.execute(query)
            task = result.scalars().first()
            return task

