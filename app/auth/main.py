from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from models.user_admin import setup_admin
from db.database import async_engine
from db.user_repository import UsersRepo
from api.api import api_routers

from utils.logging import logger

import tracemalloc

# Включаем отслеживание памяти
tracemalloc.start()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info('Запуск приложения...')
    await UsersRepo.create_tables()
    logger.debug('База перезапущена')
    yield
    logger.info('Выключение...')

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_routers)

setup_admin(app, async_engine)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(f"{__name__}:app", reload=True)
