from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from config import AES_key, iv, private_key
import base64

def decrypt_aes_token(token):
    """Расшифровка токена с помощью AES."""
    cipher = AES.new(AES_key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(token), AES.block_size)

def decrypt_rsa_session_key(session_key):
    """Расшифровка sessionKey с помощью RSA."""
    return private_key.decrypt(
        session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def encrypt_token(decrypted_session_key, decrypted_token_AES):
    """Шифрование токена с новым sessionKey и отправка клиенту."""
    cipher_to_send = AES.new(decrypted_session_key, AES.MODE_CBC)
    ivN = cipher_to_send.iv
    token = cipher_to_send.encrypt(pad(decrypted_token_AES, AES.block_size))
    return base64.b64encode(ivN + token).decode('utf-8')
