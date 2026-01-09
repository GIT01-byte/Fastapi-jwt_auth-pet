import fastapi
import pytest
from httpx import AsyncClient, ASGITransport
from contextlib import nullcontext as does_not_raise

from backend.auth.utils.security import ACCESS_TOKEN_TYPE, REFRESH_TOKEN_TYPE, create_refresh_token, hash_token
from backend.auth.core.schemas import JWTPayload
from backend.auth.main import app


class TestTokens:
    def test_create_refresh_token(self):
        token, hashed_token = create_refresh_token()
        assert isinstance(token, str)
        assert isinstance(hashed_token, str)

class TestApi:
    @pytest.mark.asyncio
    async def test_unauthorize_user(self, ac):
        response = await ac.get("/me/")
        assert response.status_code == 401
    
    
    @pytest.mark.parametrize(
        "login_data",
        [
            {"username": "test_user", "password": "1234test"},
            {"username": "test_user_1", "password": "5678test"},
        ]
    )
    @pytest.mark.asyncio
    async def test_authorize_user(self, ac: AsyncClient, login_data: dict):
        # 1. Вход юзера в систему
        response_login = await ac.post("/login/", data=login_data)
        
        assert response_login.status_code == 200
        data = response_login.json()
        
        # Проверка токенов в теле ответа
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"].lower() == "bearer"
        
        # Проверка кук 
        assert ACCESS_TOKEN_TYPE in response_login.cookies
        assert REFRESH_TOKEN_TYPE in response_login.cookies
        
        # 2. Проверка доступа к защищенному эндпоинту
        token = data["access_token"]
        headers = {'Authorization': f'Bearer {token}'}
        response_info = await ac.get("/me/", headers=headers)
        
        assert response_info.status_code == 200
        
        # 3. Дополнительная проверка: убедимся, что вернулся именно тот юзер
        info_data = response_info.json()
        assert info_data["username"] == login_data["username"]
