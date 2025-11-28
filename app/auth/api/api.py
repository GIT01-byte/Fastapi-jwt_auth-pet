from fastapi import APIRouter

from api import authentication

api_routers = APIRouter()

api_routers.include_router(authentication.router, tags=["authentication"], prefix="/users") # type: ignore
