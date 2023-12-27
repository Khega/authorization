from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

        return f(data, *args, **kwargs)

    return decorated


@app.route('/login', methods=['POST'])
def login():
    try:
        auth = request.authorization

        if auth and auth.password == 'password':
            token = jwt.encode({'user': auth.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                               app.config['SECRET_KEY'])
            return {'token': token}

        return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        print(f"Error in login: {str(e)}")
        return {'error': 'Internal Server Error'}, 500


@app.route('/protected', methods=['GET'])
@token_required
def protected(data):
    return jsonify({'message': 'This is a protected route', 'user': data['user']})


if __name__ == '__main__':
    app.run(debug=True)
