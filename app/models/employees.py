from typing import Optional
from pydantic import BaseModel
from sqlalchemy import Boolean
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

class Base(DeclarativeBase):
    pass

class EmployeesOrm(Base):
    __tablename__ = 'employees' 
    
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    last_name Mapped[str]
    phone Mapped[int]
    image_url Mapped[str]
