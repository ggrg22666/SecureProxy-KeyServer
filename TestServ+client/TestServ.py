from flask import Flask, request, jsonify

Serv = Flask(__name__)

@Serv.route("/TestServer", methods=["POST"])
def main():
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        return jsonify({"error": "Authorization header missing"}), 401

    # Здесь можно добавить проверку валидности токена, если это необходимо

    return jsonify({
        'completed': False,
        'id': 200,
        'title': 'ipsam aperiam voluptates qui',
        'userId': 10
    }), 200

if __name__ == '__main__':
    Serv.run(debug=True, port=5005, host='0.0.0.0')
