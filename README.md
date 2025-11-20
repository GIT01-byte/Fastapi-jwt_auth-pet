# Fastapi-auth-test-task

## Что это такое?

Это простой API веб-сервис с возможностью jwt аунтеффикации

## Что тебе понадобится, чтобы запустить:

*   **Python 3.9+** 

## Как запустить:

1.  Клонируйте репозиторий:
    ```bash
    git clone https://github.com/GIT01-byte/Fastapi-auth_test_task
    cd "Fastapi-auth_test_task"
    ```
    
2.  Установите зависимости:
    ```bash
    python -m venv .venv
    .\.venv\Scripts\activate
    pip install -r requirements.txt
    ```
    
3. Установи публичный и приватный ключи безопастности:
   ```bash
   cd app/auth/utils
   python gen_keys
   ```
   
5.  **Запусти сервер:**
    ```bash
    uvicorn main:app --reload
    ```

## Как пользоваться API:

После запуска, открой браузер и перейди по этим ссылкам:

*   **Документация (очень удобно!):** `http://127.0.0.1:8000/docs`
    Здесь ты увидишь все команды, которые умеет выполнять твой API, и сможешь их протестировать.

*   **Альтернативная документация:** `http://127.0.0.1:8000/redoc`

---
