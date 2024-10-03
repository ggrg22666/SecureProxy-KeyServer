import requests

SecureProxy = 'http://127.0.0.1:5004/request_api'

data_req = {
    "ClientId": "client4",
    "TokenType": "token4",
    "ApiUri": "http://testserv:5005/TestServer"
}

response = requests.post(SecureProxy, json=data_req)

if response.status_code == 200:
    print("Ответ сервера: ", response.json())
else:
    print(f"Ошибка {response.status_code}: {response.text}")
