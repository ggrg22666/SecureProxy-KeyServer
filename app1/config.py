from cryptography.hazmat.primitives.asymmetric import rsa
import os

# Генерация пары ключей RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# Загрузка ключа AES и IV из файлов
with open('key.bin', 'rb') as f:
    AES_key = f.read()

with open('iv.bin', 'rb') as f:
    iv = f.read(16)

# Конфигурация базы данных
db_config = {
    'host': os.getenv('DB_HOST', 'mysql'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', 'Labi6123'),
    'database': os.getenv('DB_NAME', 'token_api')
}