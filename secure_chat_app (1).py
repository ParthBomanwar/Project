from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# In-memory storage for simplicity
users = {}  # {username: {'public_key': ..., 'private_key': ...}}
chat_logs = {}  # {room: [(encrypted_message, sender, iv)]}

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_key(key, is_private=False):
    if is_private:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKey
    ).decode('utf-8')

def deserialize_key(key_pem, is_private=False):
    if is_private:
        return serialization.load_pem_private_key(
            key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
    return serialization.load_pem_public_key(
        key_pem.encode('utf-8'),
        backend=default_backend()
    )

def encrypt_message(message, recipient_public_key):
    # Generate AES key and IV
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)       # 128-bit IV

    # Encrypt message with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = message.encode('utf-8') + b' ' * (16 - len(message) % 16)
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    # Encrypt AES key with recipient's RSA public key
    encrypted_aes_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return base64.b64encode(encrypted_message).decode('utf-8'), \
           base64.b64encode(encrypted_aes_key).decode('utf-8'), \
           base64.b64encode(iv).decode('utf-8')

def decrypt_message(encrypted_message, encrypted_aes_key, iv, private_key):
    # Decrypt AES key with private key
    aes_key = private_key.decrypt(
        base64.b64decode(encrypted_aes_key),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt message with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(base64.b64decode(iv)), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(base64.b64decode(encrypted_message)) + decryptor.finalize()
    return decrypted_padded.rstrip().decode('utf-8')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.json['username']
    if username in users:
        return jsonify({'error': 'Username exists'}), 400
    
    private_key, public_key = generate_key_pair()
    users[username] = {
        'public_key': serialize_key(public_key),
        'private_key': serialize_key(private_key, is_private=True)
    }
    return jsonify({
        'public_key': users[username]['public_key'],
        'private_key': users[username]['private_key']
    })

@app.route('/get_public_key/<username>')
def get_public_key(username):
    if username not in users:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'public_key': users[username]['public_key']})

@socketio.on('join')
def on_join(data):
    username = data['username']
    room = data['room']
    join_room(room)
    
    # Send chat history
    if room in chat_logs:
        emit('chat_history', {'messages': chat_logs[room]}, room=request.sid)

@socketio.on('message')
def handle_message(data):
    sender = data['sender']
    recipient = data['recipient']
    message = data['message']
    room = data['room']

    if recipient not in users:
        emit('error', {'message': 'Recipient not found'})
        return

    recipient_public_key = deserialize_key(users[recipient]['public_key'])
    encrypted_message, encrypted_aes_key, iv = encrypt_message(message, recipient_public_key)

    # Store encrypted message
    if room not in chat_logs:
        chat_logs[room] = []
    chat_logs[room].append({
        'encrypted_message': encrypted_message,
        'encrypted_aes_key': encrypted_aes_key,
        'iv': iv,
        'sender': sender
    })

    # Broadcast encrypted message
    emit('message', {
        'encrypted_message': encrypted_message,
        'encrypted_aes_key': encrypted_aes_key,
        'iv': iv,
        'sender': sender
    }, room=room)

if __name__ == '__main__':
    socketio.run(app, debug=True)