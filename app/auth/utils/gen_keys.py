import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Определяем путь к директории для ключей
BASE_DIR = Path(__file__).parent.parent
KEY_DIR = f"{BASE_DIR}/certs"

# 0. Проверка и создание директории, если её нет
if not os.path.exists(KEY_DIR):
    os.makedirs(KEY_DIR)
    print(f"Директория '{KEY_DIR}' была создана.")
else:
    print(f"Директория '{KEY_DIR}' уже существует.")

# 1. Генерация ключей
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# 2. Сериализация закрытого ключа в PEM-формат и запись в файл
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open(os.path.join(KEY_DIR, "private_key.pem"), "wb") as f:
    f.write(pem_private)

# 3. Сериализация открытого ключа в PEM-формат и запись в файл
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open(os.path.join(KEY_DIR, "public_key.pem"), "wb") as f:
    f.write(pem_public)

print(f"Ключи успешно записаны в файлы {KEY_DIR}/private_key.pem и {KEY_DIR}/public_key.pem")
