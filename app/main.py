import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
import uvicorn

from api.api import router as api_router
from db.database import create_table, delete_table


@asynccontextmanager
async def lifespan(app: FastAPI):
    print('[INFO]    Приложение запущено...')
    # await asyncio.to_thread(delete_table)
    # await asyncio.to_thread(create_table)
    # print('[INFO]    База перезапущена...')
    yield
    print('[INFO]    Выключение!')

app = FastAPI(lifespan=lifespan)

app.include_router(api_router)


if __name__ == '__main__':
    uvicorn.run(f'{__name__}:app', reload=True, host='127.0.0.1', port=8000)
