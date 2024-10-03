from flask import Flask, jsonify, request
from db import get_db_connection
from crypto_utils import decrypt_aes_token, decrypt_rsa_session_key, encrypt_token
from config import public_key
from cryptography.hazmat.primitives import serialization
import base64
import time
import logging
import re

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
app = Flask(__name__)


def validate_request(data):
    logging.info("Валидация запроса: %s", data)
    if not isinstance(data.get('sessionKey'), str) or not re.match(r'^[A-Za-z0-9+/=]+$', data['sessionKey']):
        logging.error("Неверный формат sessionKey")
        return False, 'Неверный формат sessionKey'
    if not isinstance(data.get('clientId'), str) or len(data['clientId']) < 1:
        logging.error("Неверный clientId")
        return False, 'Неверный clientId'
    if not isinstance(data.get('tokenType'), str) or len(data['tokenType']) < 1:
        logging.error("Неверный tokenType")
        return False, 'Неверный tokenType'
    if not isinstance(data.get('timestamp'), int):
        logging.error("Неверный timestamp")
        return False, 'Неверный timestamp'
    if not isinstance(data.get('nonce'), str) or len(data['nonce']) < 1:
        logging.error("Неверный nonce")
        return False, 'Неверный nonce'
    logging.info("Валидация запроса пройдена успешно")
    return True, None


used_nonces = set()


def validate_timestamp_and_nonce(timestamp, nonce):
    current_time = int(time.time())
    logging.info("Проверка временной метки и nonce: timestamp=%d, nonce=%s", timestamp, nonce)
    if abs(current_time - timestamp) > 300:
        logging.error("Временная метка недействительна")
        return False, 'Временная метка недействительна'
    if nonce in used_nonces:
        logging.error("Nonce уже был использован")
        return False, 'Nonce уже был использован'
    used_nonces.add(nonce)
    logging.info("Проверка временной метки и nonce пройдена")
    return True, None


@app.route('/public_key', methods=['POST'])
def send_public_key():
    """Отправка публичного ключа клиенту."""
    logging.info("Отправка публичного ключа")
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jsonify({'public_key': pem.decode('utf-8')})


@app.route('/', methods=['POST'])
def handle_request():
    logging.info("Получен запрос: %s", request.json)
    is_valid, error = validate_request(request.json)
    if not is_valid:
        logging.error("Ошибка валидации запроса: %s", error)
        return jsonify({'ОШИБКА': error}), 400

    timestamp = request.json['timestamp']
    nonce = request.json['nonce']
    is_valid, error = validate_timestamp_and_nonce(timestamp, nonce)
    if not is_valid:
        logging.error("Ошибка валидации временной метки и nonce: %s", error)
        return jsonify({'ОШИБКА': error}), 400

    session_key = request.json['sessionKey']
    client_id = request.json['clientId']
    token_type = request.json['tokenType']

    try:
        logging.info("Декодирование sessionKey из Base64")
        session_key = base64.b64decode(session_key)
    except Exception as e:
        logging.error("Неверный формат sessionKey: %s", str(e))
        return jsonify({'ОШИБКА': f'Неверный формат sessionKey: {str(e)}'}), 400

    # Подключение к базе данных
    logging.info("Подключение к базе данных")
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        # Поиск токена в базе данных
        query = "SELECT token FROM storage WHERE client_id = %s AND token_type = %s"
        logging.info("Выполнение запроса к БД: %s", query)
        cursor.execute(query, (client_id, token_type))
        cursor_fd = cursor.fetchone()

        if cursor_fd:
            token = cursor_fd[0]
            try:
                logging.info("Исходный токен (до расшифровки): %s", token)

                # Преобразуем токен из строки в байты, если это необходимо
                if isinstance(token, str):
                    token = base64.b64decode(token)
                    logging.info("Токен после декодирования из base64: %s", token)

                logging.info("Попытка расшифровки токена с использованием AES")
                decrypted_token_AES = decrypt_aes_token(token)
                logging.info("Токен успешно расшифрован с помощью AES")

                logging.info("Попытка расшифровки sessionKey с использованием RSA")
                decrypted_session_key = decrypt_rsa_session_key(session_key)
                logging.info("sessionKey успешно расшифрован с помощью RSA")

                logging.info("Шифрование токена с новым sessionKey")
                TokenEncryptedWithSessionAesKey = encrypt_token(decrypted_session_key, decrypted_token_AES)
                logging.info("Токен успешно зашифрован с новым sessionKey")

                logging.info("Запрос успешно обработан")
                return jsonify({"token": TokenEncryptedWithSessionAesKey})
            except Exception as e:
                logging.error("Ошибка при расшифровке токена или sessionKey: %s", str(e))
                return jsonify({'ОШИБКА': str(e)}), 500
        else:
            logging.error("Токен не найден")
            return jsonify({'ОШИБКА': 'Токен не найден'}), 404

    finally:
        logging.info("Закрытие подключения к базе данных")
        cursor.close()
        connection.close()


if __name__ == '__main__':
    logging.info("Запуск приложения Flask")
    app.run(debug=True, port=5001, host='0.0.0.0')