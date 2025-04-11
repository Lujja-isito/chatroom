from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_socketio import SocketIO, join_room, emit, leave_room
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sqlite3
from datetime import datetime
from functools import wraps
import secrets
import sys

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SESSION_TYPE'] = 'filesystem'

# Initialize SocketIO with CORS support
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

# In-memory storage (replace with database in production)
users = {}
rooms = {
    'general': {
        'members': {},
        'messages': []
    }
}

# Routes
@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/interface')
def interface():
    return render_template('interface.html')

@socketio.on('connect')
def handle_connect():
    print('Client connected')

def validate_message(f):
    @wraps(f)
    def wrapper(data):
        if not all(k in data for k in ['sender', 'room', 'message']):
            emit('error', {"message": "Invalid message format"})
            return
        if len(data['message']) > 1000:
            emit('error', {"message": "Message too Long"})
            return
        return f(data)
    return wrapper

@socketio.on('send_message')
@validate_message
def handle_message(data):
    sender = data['sender']
    room = data['room']
    message = data['message']
    save_message(room, sender, message)

    # Get the list of recipients (excluding the sender)
    recipients_list = [u for u in active_rooms.get(room, []) if u != sender]

    # Only proceed with the query if there are recipients
    if recipients_list:
        # Get all recipients' public keys
        conn = sqlite3.connect('chat.db')
        c = conn.cursor()
        c.execute("SELECT username, public_key FROM users WHERE username IN ({})".format(','.join(['?'] * len(recipients_list))),
                  recipients_list)
        recipients = c.fetchall()
        conn.close()

        # Encrypt for each recipient
        encrypted_message = {}
        for username, pub_key in recipients:
            public_key = RSA.import_key(pub_key)
            encrypted_message[username] = encrypt_message_hybrid(message, public_key)

        # Emit the message to the room
        emit('room_message', {
            "sender": sender,
            "message": message,
            "encrypted_message": encrypted_message,
            "timestamp": datetime.now().isoformat()
        }, room=room)
    else:
        # If there are no recipients, just save the message and emit it to the sender
        emit('room_message', {
            "sender": sender,
            "message": message,
            "encrypted_message": {},
            "timestamp": datetime.now().isoformat()
        }, to=request.sid)

@socketio.on('typing')
def handle_typing(data):
    emit('user_typing', {
        'username': data['username']
    }, broadcast=True)

@socketio.on('stop_typing')
def handle_stop_typing():
    emit('user_stopped_typing', broadcast=True)

def Init_db():
    try:
        # Print the current working directory to confirm where the database will be created
        print(f"Current working directory: {os.getcwd()}", file=sys.stdout, flush=True)
        
        # Connect to the database
        conn = sqlite3.connect('chat.db')
        print("Successfully connected to chat.db", file=sys.stdout, flush=True)
        
        c = conn.cursor()
        
        # Create the users table
        c.execute('''CREATE TABLE IF NOT EXISTS users 
                     (username TEXT PRIMARY KEY, password TEXT, public_key TEXT, private_key TEXT)''')
        print("Users table created or already exists", file=sys.stdout, flush=True)
        
        # Create the messages table
        c.execute('''CREATE TABLE IF NOT EXISTS messages 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, room TEXT, sender TEXT, message TEXT, 
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        print("Messages table created or already exists", file=sys.stdout, flush=True)
        
        # Commit the changes and close the connection
        conn.commit()
        print("Changes committed", file=sys.stdout, flush=True)
        
        conn.close()
        print("Database connection closed", file=sys.stdout, flush=True)
        
        # Verify the database file exists
        if os.path.exists('chat.db'):
            print("chat.db file successfully created", file=sys.stdout, flush=True)
        else:
            print("chat.db file was not created", file=sys.stdout, flush=True)
            
    except sqlite3.Error as e:
        print(f"SQLite error occurred: {e}", file=sys.stdout, flush=True)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stdout, flush=True)

print("About to call Init_db()...", file=sys.stdout, flush=True)
Init_db()

def encrypt_message_rsa(message, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted = cipher_rsa.encrypt(message.encode())
    return base64.b64encode(encrypted).decode()

def encrypt_message_hybrid(message, public_key):
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_msg = cipher_aes.encrypt(pad(message.encode(), AES.block_size))
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)

    return {
        'iv': base64.b64encode(iv).decode(),
        'message': base64.b64encode(encrypted_msg).decode(),
        'key': base64.b64encode(encrypted_key).decode()
    }

def save_message(room, sender, message):
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute("INSERT INTO messages (room, sender, message) VALUES (?, ?, ?)", (room, sender, message))
    conn.commit()
    conn.close()

users_db = {}
chat_rooms = {}

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute("SELECT password, public_key FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()

    if not user or not check_password_hash(user[0], password):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity=username)
    return jsonify({"access_token": access_token, "public_key": user[1]})

active_rooms = {}

@socketio.on('join_room')
def handle_join(data):
    username = data['username']
    room = data['room']

    join_room(room)
    if room not in active_rooms:
        active_rooms[room] = []

    active_rooms[room].append(username)

    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute("SELECT sender, message FROM messages WHERE room=? ORDER BY timestamp DESC LIMIT 50", (room,))
    history = [{"sender": row[0], "message": row[1]} for row in c.fetchall()]
    conn.close()
    emit('room_history', history)
    emit('room_message', {"system": True, "message": f"{username} joined {room}"}, room=room)

@socketio.on('leave_room')
def handle_leave(data):
    username = data['username']
    room = data['room']

    if room in active_rooms and username in active_rooms[room]:
        active_rooms[room].remove(username)
        leave_room(room)
        emit('room_message', {"system": True, "message": f"{username} left {room}"}, room=room)

@socketio.on('disconnect')
def handle_disconnect():
    pass

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)