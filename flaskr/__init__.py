import secrets
import string
from flask import Flask, render_template, request, session, redirect, url_for, g, flash
from flask_bcrypt import Bcrypt
from authlib.integrations.flask_client import OAuth
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

    # Google OAuth configuration
    app.config['GOOGLE_CLIENT_ID'] = '484213283363-0lr7vmgdk81h02f8e9p8pgalq1n9ov6v.apps.googleusercontent.com'
    app.config['GOOGLE_CLIENT_SECRET'] = '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'

    oauth = OAuth(app)
    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        access_token_url='https://oauth2.googleapis.com/token',
        userinfo_endpoint='https://www.googleapis.com/oauth2/v3/userinfo',
        jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
        client_kwargs={'scope': 'openid profile email'},
    )

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

    @app.route('/google/login')
    def google_login():
        state = secrets.token_urlsafe(32)
        session['google_oauth_state'] = state
        redirect_uri = url_for('google_callback', _external=True)
        print(f"Redirect URI: {redirect_uri}")  
        return oauth.google.authorize_redirect(redirect_uri, state=state)

    @app.route('/google/callback')
    def google_callback():
        state_in_request = request.args.get('state')
        state_in_session = session.get('google_oauth_state')
        print(f"State in request: {state_in_request}")
        print(f"State in session: {state_in_session}")

        if state_in_request != state_in_session:
            return 'Error: State mismatch', 400

        token = oauth.google.authorize_access_token()
        resp = oauth.google.get('https://www.googleapis.com/oauth2/v3/userinfo')
        user_info = resp.json()

        session['profile'] = user_info
        session.permanent = True

        return redirect(url_for('index'))

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        msg = ''
        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            confirm_password = request.form['confirm_password']

            if password != confirm_password:
                msg = 'Passwords do not match!'
                return render_template('signup.html', msg=msg)

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            try:
                db = get_db()
                cursor = db.cursor()
                cursor.execute('INSERT INTO User (username, email, password) VALUES (%s, %s, %s)', (username, email, hashed_password))
                db.commit()
                cursor.close()
                return redirect(url_for('login'))
            except IntegrityError:
                msg = 'Username or email address already exists. Please use a different username or email.'
            except Error as e:
                msg = f'An error occurred: {e}'
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