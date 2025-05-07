from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import mysql.connector

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = '7b47afe9e7548d8fa383da03d16691f2b656cf25415a516c80299e2335e6e8bd'
CORS(app)

db_config = {
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': '',
    'database': 'medovia'
}

jwt = JWTManager(app)

def get_db_connection():
    return mysql.connector.connect(**db_config)

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = data['password']

    hashed_pw = generate_password_hash(password)

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
            (username, email, hashed_pw)
        )
        conn.commit()
        return jsonify(message="User created"), 201
    except mysql.connector.IntegrityError:
        return jsonify(message="Username or email already exists"), 409
    finally:
        cursor.close()
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if user and check_password_hash(user['password'], password):
        access_token = create_access_token(identity=email)
        return jsonify(access_token=access_token)

    return jsonify(message="Invalid credentials"), 401

@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    return jsonify(message=f"Welcome, {current_user}!")

if __name__ == '__main__':
    app.run(debug=True)
