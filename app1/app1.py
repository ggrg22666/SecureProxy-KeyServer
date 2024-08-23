from flask import Flask, jsonify, request
from db import get_db_connection
from crypto_utils import decrypt_aes_token, decrypt_rsa_session_key, encrypt_token
from config import public_key
from cryptography.hazmat.primitives import serialization
import base64
import time
import re

app = Flask(__name__)

def validate_request(data):
    if not isinstance(data.get('sessionKey'), str) or not re.match(r'^[A-Za-z0-9+/=]+$', data['sessionKey']):
        return False, 'Неверный формат sessionKey'
    if not isinstance(data.get('clientId'), str) or len(data['clientId']) < 1:
        return False, 'Неверный clientId'
    if not isinstance(data.get('tokenType'), str) or len(data['tokenType']) < 1:
        return False, 'Неверный tokenType'
    if not isinstance(data.get('timestamp'), int):
        return False, 'Неверный timestamp'
    if not isinstance(data.get('nonce'), str) or len(data['nonce']) < 1:
        return False, 'Неверный nonce'
    return True, None

used_nonces = set()
def validate_timestamp_and_nonce(timestamp, nonce):
    current_time = int(time.time())
    # Проверка, что временная метка находится в пределах 5 минут
    if abs(current_time - timestamp) > 300:
        return False, 'Временная метка недействительна'
    # Проверка, что nonce уникален
    if nonce in used_nonces:
        return False, 'Nonce уже был использован'
    used_nonces.add(nonce)
    return True, None

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
    is_valid, error = validate_request(request.json)
    if not is_valid:
        return jsonify({'ОШИБКА': error}), 400

    # Проверка временной метки и nonce
    timestamp = request.json['timestamp']
    nonce = request.json['nonce']
    is_valid, error = validate_timestamp_and_nonce(timestamp, nonce)
    if not is_valid:
        return jsonify({'ОШИБКА': error}), 400

    session_key = request.json['sessionKey']
    client_id = request.json['clientId']
    token_type = request.json['tokenType']

    try:
        # Декодирование sessionKey из Base64
        session_key = base64.b64decode(session_key)
    except Exception as e:
        return jsonify({'ОШИБКА': f'Неверный формат sessionKey: {str(e)}'}), 400

    # Подключение к базе данных
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        # Поиск токена в базе данных
        query = "SELECT token FROM storage WHERE client_id = %s AND token_type = %s"
        cursor.execute(query, (client_id, token_type))
        cursor_fd = cursor.fetchone()

        if cursor_fd:
            token = cursor_fd[0]
            try:
                # Расшифровка токена с использованием AES
                decrypted_token_AES = decrypt_aes_token(token)
                # Расшифровка sessionKey с использованием RSA
                decrypted_session_key = decrypt_rsa_session_key(session_key)
                # Шифрование токена с новым sessionKey для отправки клиенту
                TokenEncryptedWithSessionAesKey = encrypt_token(decrypted_session_key, decrypted_token_AES)
                return jsonify({"token": TokenEncryptedWithSessionAesKey})
            except Exception as e:
                return jsonify({'ОШИБКА': str(e)}), 500
        else:
            return jsonify({'ОШИБКА': 'Токен не найден'}), 404

    finally:
        # Закрытие подключения к базе данных
        cursor.close()
        connection.close()


if __name__ == '__main__':
    app.run(debug=True, port=5001, host='0.0.0.0')