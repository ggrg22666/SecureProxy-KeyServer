from flask import Flask, jsonify, request
from db import get_db_connection
from crypto_utils import decrypt_aes_token, decrypt_rsa_session_key, encrypt_token
from config import public_key
from cryptography.hazmat.primitives import serialization
import base64

app = Flask(__name__)


@app.route('/public_key', methods=['POST'])
def send_public_key():
    """Отправка публичного ключа клиенту."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jsonify({'public_key': pem.decode('utf-8')})


@app.route('/', methods=['POST'])
def handle_request():
    """Обработка запроса для получения токена."""
    connection = get_db_connection()
    cursor = connection.cursor()

    session_key = request.json.get('sessionKey')
    client_id = request.json.get('clientId')
    token_type = request.json.get('tokenType')

    try:
        session_key = base64.b64decode(session_key)
    except Exception as e:
        return jsonify({'ОШИБКА': f'Неверный формат sessionKey: {str(e)}'}), 400

    query = "SELECT token FROM storage WHERE client_id = %s AND token_type = %s"
    cursor.execute(query, (client_id, token_type))
    cursor_fd = cursor.fetchone()

    cursor.close()
    connection.close()

    if cursor_fd:
        token = cursor_fd[0]
        try:
            decrypted_token_AES = decrypt_aes_token(token)
            decrypted_session_key = decrypt_rsa_session_key(session_key)
            TokenEncryptedWithSessionAesKey = encrypt_token(decrypted_session_key, decrypted_token_AES)
            return jsonify({"token": TokenEncryptedWithSessionAesKey})
        except Exception as e:
            return jsonify({'ОШИБКА': str(e)}), 500
    else:
        return jsonify({'ОШИБКА': 'Токен не найден'}), 404


if __name__ == '__main__':
    app.run(debug=True, port=5001, host='0.0.0.0')
