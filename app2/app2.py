import time
import uuid
import requests
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives import serialization
from crypto_utils import generate_session_key, encrypt_session_key, decrypt_token
from config import PUBLIC_KEY_URL, TOKEN_REQUEST_URL

app = Flask(__name__)


def get_public_key():
    response = requests.post(PUBLIC_KEY_URL)
    response.raise_for_status()
    data = response.json()
    public_key_pem = data['public_key'].encode('utf-8')
    public_key = serialization.load_pem_public_key(public_key_pem)
    return public_key


def request_token(encrypted_session_key, client_id, token_type):
    timestamp = int(time.time())
    nonce = str(uuid.uuid4())

    act_req = {
        "sessionKey": encrypted_session_key,
        "clientId": client_id,
        "tokenType": token_type,
        "timestamp": timestamp,
        "nonce": nonce
    }
    response = requests.post(TOKEN_REQUEST_URL, json=act_req)
    response.raise_for_status()
    return response.json().get('token')


@app.route('/request_api', methods=['POST'])
def request_api():
    public_key = get_public_key()
    session_key = generate_session_key()
    encrypted_session_key = encrypt_session_key(session_key, public_key)

    ClientId = request.json.get("ClientId")
    TokenType = request.json.get("TokenType")
    ApiUri = request.json.get("ApiUri")
    encrypted_token_b64 = request_token(encrypted_session_key, ClientId, TokenType)
    decodedToken = decrypt_token(encrypted_token_b64, session_key).decode('utf-8')

    api_response = requests.get(ApiUri, headers={
        "Authorization": f"Bearer {decodedToken}"
    })
    return jsonify(api_response.json())


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004)
