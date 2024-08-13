import mysql.connector
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


with open('app1/key.bin', 'rb') as f:
    AES_key = f.read()
with open('app1/iv.bin', 'rb') as g:
    iv = g.read(16)
message = b'Token2'


def encrypt_data():
    cipher = AES.new(AES_key, AES.MODE_CBC, iv=iv)
    ciphered_data = cipher.encrypt(pad(message, AES.block_size))
    return ciphered_data
conn = mysql.connector.connect(
    host='localhost',
    user='root',
    password='Labi6123',
    database='token_api'
)

cursor = conn.cursor()

encrypted_token = encrypt_data()

query = "INSERT INTO storage (client_id, token_type, token) VALUES (%s, %s, %s)"
cursor.execute(query, ('client2', 'token2', encrypted_token))

# Сохранение изменений
conn.commit()

# Закрытие соединения
cursor.close()
conn.close()
