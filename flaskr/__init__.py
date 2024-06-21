import secrets
import string
from flask import Flask, render_template
from flask_socketio import SocketIO
from flask_socketio import emit
from flask import request

clients = {}
broadcastKeys = {}
allClients = {}

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
    clients[data['recipient']] = request.sid
    broadcastKeys[data['recipient']] = data['publicKey']
    allClients[request.sid] = data['recipient']
    # emit("allUsers", {"username": data['recipient'], "publicKey": data['publicKey']}, broadcast=True)
    emit("allUsers", {"allUserKeys": broadcastKeys}, broadcast=True)
    print(data['publicKey'])

@socketio.on('message')
def handle_message(data):
    recipient = data['recipient_name']
    if recipient in clients:
        recipient_sid = clients[recipient]
        emit('message', {'message': data['message'], 'sender': allClients[request.sid]}, room=recipient_sid)
    else:
        print('Recipient not connected.')

@socketio.on('new_message')
def handle_new_message(message):
    print(f"New Message : {message}")
    username = None
    for user in clients:
        if user == request.sid:
            username = clients[request.sid]
    emit("chat", {"message": message, "username": username}, broadcast=True)

if __name__ == "__main__":
    # app.run(host='0.0.0.0', port='8080') # indent this line
    socketio.run(app) # indent this line