import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def generate_session_key():
    """Генерация sessionKey с использованием случайного ключа."""
    return get_random_bytes(32)


def encrypt_session_key(session_key, public_key):
    """Шифрование sessionKey с помощью публичного ключа."""
    encrypted_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode('utf-8')


def decrypt_token(encrypted_token_b64, session_key):
    """Расшифровка полученного токена."""
    token_iv = base64.b64decode(encrypted_token_b64)
    iv = token_iv[:16]
    token = token_iv[16:]
    cipher = AES.new(session_key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(token), AES.block_size)
