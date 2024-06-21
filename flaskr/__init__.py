import secrets
import string
from flask import Flask, render_template
from flask_socketio import SocketIO
from flask_socketio import emit
from flask import request

users = {}
userKeys = {}
broadcastKeys = {}

def generate_secret_key(length=32):
    alphabet = string.ascii_letters + string.digits + '!@#$%^&*()-=_+'
    return ''.join(secrets.choice(alphabet) for _ in range(length))

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = generate_secret_key()
socketio = SocketIO(app)

@app.route("/")#URL leading to method
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect(data):
    print('Client Connected')

@socketio.on('user_join')
def handle_user_join(data):
    print(f"User {data['recipient']} Joined!")
    users[request.sid] = data['recipient']
    userKeys[request.sid] = data['publicKey']
    broadcastKeys[data['recipient']] = data['publicKey']
    emit("allUsers", {"username": data['recipient'], "publicKey": data['publicKey']}, broadcast=True)
    print(data['publicKey'])

@socketio.on('new_message')
def handle_new_message(message):
    print(f"New Message : {message}")
    username = None
    for user in users:
        if user == request.sid:
            username = users[request.sid]
    emit("chat", {"message": message, "username": username}, broadcast=True)

if __name__ == "__main__":
    # app.run(host='0.0.0.0', port='8080') # indent this line
    socketio.run(app) # indent this line