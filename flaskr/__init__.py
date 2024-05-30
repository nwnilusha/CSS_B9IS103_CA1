from flask import Flask, render_template
from flask_socketio import SocketIO
from flask_socketio import emit
from flask import request

users = {}

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'secret_key'
socketio = SocketIO(app)

@app.route("/")#URL leading to method
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect(data):
    print('Client Connected')

@socketio.on('user_join')
def handle_user_join(username):
    print(f"User {username} Joined!")
    users[username] = request.sid

@socketio.on('new_message')
def handle_new_message(message):
    print(f"New Message : {message}")
    username = None
    for user in users:
        if users[user] == request.sid:
            username = user
    emit("chat", {"message": message, "username": username}, broadcast=True)

if __name__ == "__main__":
    # app.run(host='0.0.0.0', port='8080') # indent this line
    socketio.run(app) # indent this line