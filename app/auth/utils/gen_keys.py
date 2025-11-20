# Пример с библиотекой cryptography
# Установка: pip install cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# 1. Генерация ключей
private_key = ed25519.Ed25519PrivateKey.generate()

public_key = private_key.public_key()

# 2. Сериализация закрытого ключа в PEM-формат и запись в файл
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open("./app/auth/certs/private_key.pem", "wb") as f:
    f.write(pem_private)

# 3. Сериализация открытого ключа в PEM-формат и запись в файл
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open("./app/auth/certs/public_key.pem", "wb") as f:
    f.write(pem_public)

print("Ключи успешно записаны в файлы private_key.pem и public_key.pem")