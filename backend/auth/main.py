from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse

from core.models.user_admin import setup_admin
from core.db.db_manager import db_manager
from api import api_routers

from utils.logging import logger

import tracemalloc

from prometheus_fastapi_instrumentator import Instrumentator

# Включаем отслеживание памяти, для дебага ошибок с ассинхронными функциями
tracemalloc.start()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info('Запуск приложения...')
    yield
    logger.info('Выключение...')

app = FastAPI(
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Подключаем api роутеры
app.include_router(api_routers)

# Подключаем prometheus метрики
Instrumentator().instrument(app).expose(app)

# # Подключаем админ панель
# setup_admin(app, db_manager.engine)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False, workers=1)
