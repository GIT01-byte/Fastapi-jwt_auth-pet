import fastapi
import pytest
from httpx import AsyncClient, ASGITransport
from contextlib import nullcontext as does_not_raise

from backend.auth.utils.security import ACCESS_TOKEN_TYPE, REFRESH_TOKEN_TYPE, create_refresh_token, hash_token
from backend.auth.core.schemas import JWTPayload
from backend.auth.main import app
from backend.auth.core.db.repositories import UsersRepo


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

    # TODO протетсировать ручку регистрации пользователя (и его авто-выхода)
    @pytest.mark.parametrize(
        "register_data",
        [
            {
                "username": "test_user_2",
                "email": "test_user_2@testemail.com",
                "profile": {},
                "password": "1234test"
            },
            {
                "username": "test_user_3",
                "email": "test_user_3@testemail.com",
                "password": "5678test"
            }
        ]
    )
    @pytest.mark.asyncio
    async def test_register_user(self, ac: AsyncClient, register_data: dict):
        # 1. Проверка на неавторизованного пользователя
        unautorize_response = await ac.get("/me/")
        assert unautorize_response.status_code == 401
        
        # 2. Выполнение процедуры регистрации
        response_register = await ac.post("/register/", json=register_data)
        
        assert response_register.status_code == 200
        response_data = response_register.json()
        
        # 3. Проверка выходных данных
        assert register_data["username"] in response_data["message"]
        
        # 4. Проверка пользователя в БД
        user_in_db = await UsersRepo.select_user_by_username(register_data["username"])
        
        assert user_in_db is not None, f"Пользователь {register_data['username']} не найден в БД"
        assert user_in_db.username == register_data['username']
        assert user_in_db.email == register_data['email']


    @pytest.mark.parametrize(
        "register_data",
        [
            {
                "username": "test_user_2",
                "email": "test_user_2@testemail.com",
                "profile": {},
                "password": "1234test"
            },
            {
                "username": "test_user_3",
                "email": "test_user_3@testemail.com",
                "password": "5678test"
            }
        ]
    )
    @pytest.mark.asyncio
    async def test_register_user_with_current_user(self, ac: AsyncClient, register_data: dict, auth_user):
        # 1. Вход пользоваетеля для теста авто-выхода

        
        # 2. Выполнение процедуры регистрации
        response_register = await ac.post("/register/", json=register_data)
        
        assert response_register.status_code == 200
        response_data = response_register.json()
        
        # 3. Проверка выходных данных
        assert register_data["username"] in response_data["message"]
        
        # 4. Проверка пользователя в БД
        user_in_db = await UsersRepo.select_user_by_username(register_data["username"])
        
        assert user_in_db is not None, f"Пользователь {register_data['username']} не найден в БД"
        assert user_in_db.username == register_data['username']
        assert user_in_db.email == register_data['email']
