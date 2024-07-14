import secrets
import string
from flask import Flask, render_template, request, session, redirect, url_for, g, flash
from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
import mysql.connector
import re
from flask_socketio import SocketIO, emit
from flaskr.config import Config
from flaskr.db import Database

clients = {}
broadcastKeys = {}
allClients = {}

def generate_secret_key(length=32):
    alphabet = string.ascii_letters + string.digits + '!@#$%^&*()-=_+'
    return ''.join(secrets.choice(alphabet) for _ in range(length))

socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    #app.config['MYSQL_HOST'] = 'localhost'
    #app.config['MYSQL_USER'] = 'root'
    #app.config['MYSQL_PASSWORD'] = 'password'
    #app.config['MYSQL_DB'] = 'GOBUZZ'

    # create the db config
    db_config = {
        'user': app.config['MYSQL_USER'],
        'password': app.config['MYSQL_PASSWORD'],
        'host': app.config['MYSQL_HOST'],
        'database': app.config['MYSQL_DB']
    }

    # pre-initiate the app, setup the database connection and make it available for globel context
    @app.before_request
    def before_request():
        if 'db' not in g:
            g.db = Database(db_config)
            g.db.connect()

    # disconnect the database at app teardown
    @app.teardown_appcontext
    def close_db_connection(exception):
        db = g.pop('db', None)
        if db is not None:
            db.disconnect()

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

    # Application's main page
    @app.route("/index")
    def index():
        if 'loggedin' in session:
            userData = {
                    'Username': session.get('username')
                }
        elif 'profile' in session:
            userData = {
                    'Username': session.get('email')
                }
        else:
            return redirect(url_for('login'))
        
        return render_template('index.html', userData=userData)
        

    @app.route('/', methods=['GET', 'POST'])
    def login():
        msg = ''
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            select_query = "SELECT * FROM USER WHERE username=%s"
            db = None
            try:
                db = g.get('db')

                if db is not None :
                    result = db.fetch_query(select_query, (username,))
                    if result:
                        user_data = result[0]
                        if check_password_hash(user_data['password'], password):
                            session['loggedin'] = True
                            session['username'] = user_data['email']
                            return redirect(url_for('index'))
                        else:
                            msg = "Incorrect Username or Password"
                    else:
                        msg = 'Incorrect Username or Password'
                else:
                    msg = "Database connectivity Error, Check the connection string"

            except Exception as ex:
                msg = f"Exception occurred: {ex}"
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

        if state_in_request != state_in_session:
            return 'Error: State mismatch', 400

        token = oauth.google.authorize_access_token()
        resp = oauth.google.get('https://www.googleapis.com/oauth2/v3/userinfo')
        user_info = resp.json()

        session['profile'] = user_info
        session.permanent = True

        email = user_info['email']
        session['loggedin'] = True
        session['username'] = email

        return redirect(url_for('index'))

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            msg = None

            # Validate email format
            email_pattern = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$')
            if not email_pattern.match(email):
                msg = 'Invalid email format.'
                return render_template('signup.html', msg=msg)

            # Validate password complexity
            password_pattern = re.compile(r'^(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}$')
            if not password_pattern.match(password):
                msg = 'Password must be at least 8 characters long and contain at least one special character.'
                return render_template('signup.html', msg=msg)

            # Validate password and confirm_password match
            if password != confirm_password:
                msg = 'Passwords do not match.'
                return render_template('signup.html', msg=msg)

            # Hash the password before saving to database
            hashed_password = generate_password_hash(password)

            # Check if username already exists in database
            select_query = "SELECT * FROM USER WHERE username = %s OR email = %s"
            db = None
            try:
                db = g.get('db')

                if db is not None :
                    result = db.fetch_query(select_query, (username, email))

                    if result:
                        msg = 'Username or Email already exists. Please choose a different username or email.'
                    else:
                        insert_query = 'INSERT INTO USER (username, email, password) VALUES (%s, %s, %s)'
                        result = db.execute_vquery(insert_query, username, email, hashed_password)
                        print(f"result : {result}")
                        if result >= 0:
                            return redirect(url_for('login'))
                        else:
                            msg = 'User registration failure: DB error'

                else:
                    print("DB connection is not created. Please check the connection string.")
                    msg = "Database connectivity Error, Check the connection string"

            except Exception as ex:
                print(f"Exception occurred: {ex}")
                msg = f"User registration failure: Exception occurred: {ex}"
                db = None

            if msg:
                return render_template('signup.html', msg=msg)
        return render_template('signup.html')

    @socketio.on('connect')
    def handle_connect():
        print('Client Connected')

    @socketio.on('user_join')
    def handle_user_join(data):
        print(f"User {data['recipient']} Joined!")
        clients[data['recipient']] = request.sid
        broadcastKeys[data['recipient']] = data['publicKey']
        allClients[request.sid] = data['recipient']
        # session['recipient'] = data['recipient']
        # session['sessionId'] = request.sid
        emit("allUsers", {"allUserKeys": broadcastKeys}, broadcast=True)
        print(data['publicKey'])

    @socketio.on('message')
    def handle_message(data):
        recipient = data['recipient_name']
        print("Recepient name: -------"+recipient)
        print("Recepient message: -------"+data['message'])
        if recipient in clients:
            recipient_sid = clients[recipient]
            print("Client: -------"+recipient_sid)
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

    @socketio.on('logout')
    def handle_logout(data):
        print(f"Logout Data : {data}")
        if request.sid in allClients:
            user = allClients[request.sid]
            print(f"logout user data : {user}")
            del clients[user]
            del broadcastKeys[user]
            del allClients[request.sid]
            emit("allUsers", {"allUserKeys": broadcastKeys}, broadcast=True)

            print("User logging out !!!!")
            emit('logout_redirect')
        else:
            print(f"Session ID {request.sid} not found in allClients dictionary")

    @app.route('/logout')
    def logout():
        session.pop('loggedin', None)
        session.pop('username', None)
        session.pop('profile', None) 
        session.pop('google_oauth_state', None)
        return redirect(url_for('login'))

    # comminting following method, refer to the method defined earlier.
    #@app.teardown_appcontext
    #def teardown_db(exception):
    #    close_db()

    return app

if __name__ == "__main__":
    app = create_app()
    socketio.run(app, host='0.0.0.0', port=8080, debug=True)
