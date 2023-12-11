from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.fernet import Fernet
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os
import time
import uuid
import argon2

hostName = "localhost"
serverPort = 8080

# Generate a key
key = Fernet.generate_key()

# Set the generated key as an environment variable
os.environ["NOT_MY_KEY"] = key.decode('utf-8')

# Read AES key from environment variable
KEY = os.environ.get("NOT_MY_KEY")

# Check if the key is provided
if KEY is None:
    raise ValueError("Environment variable NOT_MY_KEY not set")

# Initialize Fernet object
cipher = Fernet(KEY.encode('utf-8'))

# Path to the database file
database_file_path = 'totally_not_my_privateKeys.db'

# Check if the database file exists, and if so, delete it
if os.path.exists(database_file_path):
    os.remove(database_file_path)

# Initialize SQLite database
db_connection = sqlite3.connect('totally_not_my_privateKeys.db')
db_cursor = db_connection.cursor()

# Create a table to store keys
db_cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
''')

# Create a table to store users
db_cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
''')

# Create a table to log authentication requests
db_cursor.execute('''
    CREATE TABLE IF NOT EXISTS auth_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
''')

db_connection.commit()

# Function to insert an encrypted key into the database
def insert_key(key_data, exp):
    # Encrypt the key data using Fernet
    encrypted_key_data = cipher.encrypt(key_data)

    # Insert the encrypted key into the database
    db_cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (sqlite3.Binary(encrypted_key_data), exp))
    db_connection.commit()

# Function to retrieve an encrypted key from the database by kid
def get_key(kid):
    db_cursor.execute('SELECT key FROM keys WHERE kid = ?', (kid,))
    result = db_cursor.fetchone()

    if result:
        encrypted_key_data = result[0]
        decrypted_key_data = cipher.decrypt(encrypted_key_data)
        return decrypted_key_data
    
    return None

# Function to retrieve exp by kid
def get_exp(kid):
    db_cursor.execute('SELECT exp FROM keys WHERE kid = ?', (kid,))
    result = db_cursor.fetchone()
    return result[0] if result else None

def get_first_unexpired_key():
    current_time = datetime.datetime.utcnow()
    db_cursor.execute('SELECT key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1', (current_time,))
    result = db_cursor.fetchone()

    if result:
        encrypted_key_data = result[0]
        decrypted_key_data = cipher.decrypt(encrypted_key_data)
        return decrypted_key_data

    return None

def get_first_expired_key():
    current_time = datetime.datetime.utcnow()
    db_cursor.execute('SELECT key FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1', (current_time,))
    result = db_cursor.fetchone()

    if result:
        encrypted_key_data = result[0]
        decrypted_key_data = cipher.decrypt(encrypted_key_data)
        return decrypted_key_data

    return None


insert_key(key, datetime.datetime.utcnow() + datetime.timedelta(hours=1))
insert_key(key, datetime.datetime.utcnow() - datetime.timedelta(hours=1))

key = None

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class FixedWindowRateLimiter:
    def __init__(self, limit, window_size):
        self.limit = limit
        self.window_size = window_size
        self.request_count = 0
        self.window_start_time = time.time()

    def check_rate_limit(self):
        current_time = time.time()

        if current_time - self.window_start_time > self.window_size:
            # Reset the window if the time window has passed
            self.window_start_time = current_time
            self.request_count = 0

        if self.request_count >= self.limit:
            return False  # Rate limit exceeded

        self.request_count += 1
        return True

# Initialize rate limiter
rate_limiter = FixedWindowRateLimiter(limit=10, window_size=1)

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            # Check rate limit
            if not rate_limiter.check_rate_limit():
                self.send_response(429)  # Too Many Requests
                self.end_headers()
                return

            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }

            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                encoded_jwt = jwt.encode(token_payload, get_key(1), algorithm="HS256", headers=headers)

            # Extract username from the token payload
            username = token_payload.get('user', 'unknown_username')

            # Extract user ID based on the provided username
            db_cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            user_id_result = db_cursor.fetchone()
            user_id = user_id_result[0] if user_id_result else None

            # Log request details into the auth_logs table only for successful requests
            try:
                # If the authentication is successful, log the request details
                request_ip = self.client_address[0]  # Extract IP address from the request
                request_timestamp = datetime.datetime.utcnow()

                db_cursor.execute('''
                    INSERT INTO auth_logs (request_ip, request_timestamp, user_id)
                    VALUES (?, ?, ?)
                ''', (request_ip, request_timestamp, user_id))
                db_connection.commit()

                encoded_jwt = jwt.encode(token_payload, get_key(1), algorithm="HS256", headers=headers)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))

            except Exception as e:
                # Handle exception
                self.send_response(405)  
                self.end_headers()
                return

            return
    
        if parsed_path.path == "/register":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            user_data = json.loads(post_data.decode('utf-8'))

            try:
                # Generate a secure password using UUIDv4
                generated_password = str(uuid.uuid4())

                # Hash the password using Argon2
                password_hasher = argon2.PasswordHasher()
                hashed_password = password_hasher.hash(generated_password)

                # Store user details and hashed password in the database
                db_cursor.execute('''
                    INSERT INTO users (username, password_hash, email)
                    VALUES (?, ?, ?)
                ''', (user_data.get('username'), hashed_password, user_data.get('email')))
                db_connection.commit()

                # Respond with the generated password
                response_data = {"password": generated_password}
                self.send_response(201)  # Created
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(json.dumps(response_data), "utf-8"))

            except sqlite3.IntegrityError as e:
                # Handle the case where the email already exists
                response_data = {"error": "Email address is already registered."}
                self.send_response(400)  # Bad Request
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(json.dumps(response_data), "utf-8"))

            return
            
        self.send_response(405)
        self.end_headers()
        return


    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            key = get_key(1)
            h = key.hex()
            
            keys = {
                "keys": [
                    {
                        "alg": "HS256",
                        "kty": "AES",
                        "use": "sig",
                        "kid": "goodKID",
                        "k": h,
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            key = None
            h = None
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    db_connection.close()
    webServer.server_close()