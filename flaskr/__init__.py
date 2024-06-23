import secrets
import string
from flask import Flask, render_template, request, session, redirect, url_for, g, flash
from flask_bcrypt import Bcrypt
import mysql.connector
from mysql.connector import Error, IntegrityError
from flask_socketio import SocketIO, emit

clients = {}
broadcastKeys = {}
allClients = {}

def generate_secret_key(length=32):
    alphabet = string.ascii_letters + string.digits + '!@#$%^&*()-=_+'
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def get_db():
    if 'db' not in g:
        g.db = mysql.connector.connect(
            host='localhost',
            user='root',
            password='password',
            database='GOBUZZ'
        )
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = generate_secret_key()

    app.config['MYSQL_HOST'] = 'localhost'
    app.config['MYSQL_USER'] = 'root'
    app.config['MYSQL_PASSWORD'] = 'password'
    app.config['MYSQL_DB'] = 'GOBUZZ'

    socketio.init_app(app) 
    bcrypt = Bcrypt(app)

    @app.route("/index")
    def index():
        return render_template('index.html')

    @app.route('/', methods=['GET', 'POST'])
    def login():
        msg = ''
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            db = get_db()
            cursor = db.cursor()
            cursor.execute('SELECT * FROM USER WHERE username=%s', (username,))
            record = cursor.fetchone()
            cursor.close()

            if record and bcrypt.check_password_hash(record[3], password):  # Password is the fourth column
                session['loggedin'] = True
                session['username'] = username
                return redirect(url_for('index'))
            else:
                msg = 'Incorrect Username or Password'
                return render_template('login.html', msg=msg)
        else:
            return render_template('login.html', msg=msg)

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        msg = ''
        if request.method == 'POST':
            email = request.form['email']

            try:
                db = get_db()
                cursor = db.cursor()
                cursor.execute('INSERT INTO User (email) VALUES (%s)', (email,))
                db.commit()
                cursor.close()
                return redirect(url_for('login'))
            except IntegrityError:
                msg = 'Email address already exists. Please use a different email.'
                return render_template('signup.html', msg=msg)
            except Error as e:
                msg = f'An error occurred: {e}'
                return render_template('signup.html', msg=msg)

        return render_template('signup.html', msg=msg)

    @socketio.on('connect')
    def handle_connect():
        print('Client Connected')

    @socketio.on('user_join')
    def handle_user_join(data):
        print(f"User {data['recipient']} Joined!")
        clients[data['recipient']] = request.sid
        broadcastKeys[data['recipient']] = data['publicKey']
        allClients[request.sid] = data['recipient']
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

    @app.teardown_appcontext
    def teardown_db(exception):
        close_db()

    return app

if __name__ == "__main__":
    app = create_app()
    socketio.run(app, host='0.0.0.0', port=8080, debug=True)
