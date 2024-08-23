import requests

# URL вашего сервера API
SecureProxy = 'http://127.0.0.1:5004/request_api'

data_req = {
    "ClientId": 'client2',
    "TokenType": 'token2',
    "ApiUri": 'http://jsonplaceholder.typicode.com/todos'
}


def get_api_data():
    try:
        response = requests.post(SecureProxy, json=data_req)
        response.raise_for_status()
        data = response.json()
        return data
    except requests.RequestException as e:
        print(f"Ошибка запроса: {e}")
        return None


def main():
    data = get_api_data()
    if data:
        print("Полученные данные от сервера:")
        for item in data:
            print(item)
    else:
        print("Не удалось получить данные.")


if __name__ == "__main__":
    main()