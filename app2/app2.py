import time
import uuid
import requests
import logging
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives import serialization
from crypto_utils import generate_session_key, encrypt_session_key, decrypt_token
from config import PUBLIC_KEY_URL, TOKEN_REQUEST_URL

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

def get_public_key():
    logging.debug("Запрос публичного ключа.")
    try:
        response = requests.post(PUBLIC_KEY_URL)
        response.raise_for_status()
        data = response.json()
        public_key_pem = data['public_key'].encode('utf-8')
        public_key = serialization.load_pem_public_key(public_key_pem)
        logging.debug("Публичный ключ успешно получен.")
        return public_key
    except Exception as e:
        logging.error(f"Ошибка при запросе публичного ключа: {str(e)}")
        raise

def request_token(encrypted_session_key, client_id, token_type):
    logging.debug("Запрос токена с зашифрованным ключом сессии.")
    timestamp = int(time.time())
    nonce = str(uuid.uuid4())

    act_req = {
        "sessionKey": encrypted_session_key,
        "clientId": client_id,
        "tokenType": token_type,
        "timestamp": timestamp,
        "nonce": nonce
    }

    try:
        response = requests.post(TOKEN_REQUEST_URL, json=act_req)
        response.raise_for_status()
        logging.debug(f"Токен успешно получен для clientId: {client_id}, tokenType: {token_type}.")
        return response.json().get('token')
    except Exception as e:
        logging.error(f"Ошибка при запросе токена: {str(e)}")
        raise

@app.route('/request_api', methods=['POST'])
def request_api():
    logging.debug("Обработка запроса на API.")
    try:
        public_key = get_public_key()
        session_key = generate_session_key()
        encrypted_session_key = encrypt_session_key(session_key, public_key)

        ClientId = request.json.get("ClientId")
        TokenType = request.json.get("TokenType")
        ApiUri = request.json.get("ApiUri")

        logging.debug(f"Получены параметры запроса: ClientId={ClientId}, TokenType={TokenType}, ApiUri={ApiUri}.")

        encrypted_token_b64 = request_token(encrypted_session_key, ClientId, TokenType)
        decodedToken = decrypt_token(encrypted_token_b64, session_key).decode('utf-8')

        logging.debug("Токен успешно расшифрован и будет использоваться для отправки запроса на внешний API.")

        api_response = requests.post(ApiUri, headers={
            "Authorization": f"Bearer {decodedToken}"
        })

        logging.debug(f"Запрос на внешний API ({ApiUri}) выполнен, статус ответа: {api_response.status_code}.")
        return jsonify(api_response.json())
    except Exception as e:
        logging.error(f"Ошибка обработки API-запроса: {str(e)}")
        return jsonify({'ОШИБКА': str(e)}), 500

if __name__ == '__main__':
    logging.info("Запуск Flask сервера.")
    app.run(host='0.0.0.0', port=5004)
