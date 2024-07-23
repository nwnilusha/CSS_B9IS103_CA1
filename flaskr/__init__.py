from datetime import timedelta
import os
import secrets
import string
from flask import Flask, render_template, request, session, redirect, url_for, g, flash, jsonify
from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
import mysql.connector
import re
from flask_socketio import SocketIO, emit, join_room, leave_room
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_mail import Mail, Message
from flask_session import Session
from flaskr.config import Config
from flaskr.db import Database
from flaskr.db import DatabaseSQLite

clients = {}
clientsSID = {}
allClients = {}
newClient = {}

def generate_secret_key(length=32):
    alphabet = string.ascii_letters + string.digits + '!@#$%^&*()-=_+'
    return ''.join(secrets.choice(alphabet) for _ in range(length))

socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    Session(app)  # Initialize Flask-Session
    app.config['SESSION_PERMANENT'] = True
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
    
    mail = Mail(app)
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    #app.config['MYSQL_HOST'] = 'localhost'
    #app.config['MYSQL_USER'] = 'root'
    #app.config['MYSQL_PASSWORD'] = 'password'
    #app.config['MYSQL_DB'] = 'GOBUZZ'

    # create the db config
    if app.config['DB_TYPE'] == 'MYSQL':    
        db_config = {
            'user': app.config['MYSQL_USER'],
            'password': app.config['MYSQL_PASSWORD'],
            'host': app.config['MYSQL_HOST'],
            'database': app.config['MYSQL_DB']
        }
    elif app.config['DB_TYPE'] == 'SQLITE':
        db_config = {
            'database': app.config['SQLITE_DB'],
            'db_type': app.config['DB_TYPE']
        }

    # pre-initiate the app, setup the database connection and make it available for globel context
    @app.before_request
    def before_request():
        session.permanent = True
        if 'db' not in g:
            if app.config['DB_TYPE'] == 'SQLITE':
                g.db = DatabaseSQLite(db_config['database'])
            else:
                g.db = Database(db_config)
            g.db.connect()

    @app.route('/get_session')
    def get_session():
        if 'loggedin' in session:
            return jsonify({'status': 'active'})
        else:
            return jsonify({'status': 'inactive'})


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

    def send_verification_email(email):
        token = s.dumps(email, salt='email-confirm')
        verification_url = url_for('verify_email', token=token, _external=True)
        msg = Message('Email Verification', recipients=[email])
        msg.body = f'Please verify your email by clicking the following link: {verification_url}'
        mail.send(msg)
        flash('A verification email has been sent to your email address. Please check your inbox.', 'info')

    # Application's main page
    @app.route("/index")
    def index():
        if 'loggedin' in session:
            print(f"User loged in ------> {session['username']}")
            print(f"User email ------> {session['email']}")
            userData = {
                    'Username': session['username'],
                    'Email': session['email']
                }
        else:
            return redirect(url_for('login'))
        
        return render_template('index.html', userData=userData)
        

    @app.route('/', methods=['GET', 'POST'])
    def login():
        msg = request.args.get('message', '')  # Get the message from the query parameters
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            
            select_query = None
            db = None
            try:
                db = g.get('db')
                if db is not None:
                    if app.config['DB_TYPE'] == 'SQLITE':
                        select_query = "SELECT * FROM USER WHERE username=?"
                    else:
                        select_query = "SELECT * FROM USER WHERE username=%s"

                    result = db.fetch_query(select_query, (username,))
                    if result:
                        user_data = result[0]
                        if check_password_hash(user_data['password'], password):
                            session['loggedin'] = True
                            session['username'] = user_data['username']
                            session['email'] = user_data['email']
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
        session['username'] = email.split('@')[0] if email else 'unknown'
        session['email'] = email

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

            # Check if username or email already exists in database
            select_query = None
            if app.config['DB_TYPE'] == 'SQLITE':
                select_query = "SELECT * FROM USER WHERE username = ? OR email = ?"
            else:
                select_query = "SELECT * FROM USER WHERE username = %s OR email = %s"

            
            db = None
            try:
                db = g.get('db')
                if db is not None:
                    result = db.fetch_query(select_query, (username, email))
                    insert_query = None
                    if result:
                        msg = 'Username or Email already exists. Please choose a different username or email.'
                    else:
                        if app.config['DB_TYPE'] == 'SQLITE':
                            insert_query = 'INSERT INTO USER (username, email, password) VALUES (?, ?, ?)'
                            result = db.execute_vquery(insert_query, (username, email, hashed_password,))
                        else:
                            insert_query = 'INSERT INTO USER (username, email, password) VALUES (%s, %s, %s)'
                            result = db.execute_vquery(insert_query, username, email, hashed_password)

                        
                        print(f"result : {result}")
                        if result >= 0:
                            send_verification_email(email)
                            return redirect(url_for('verify_notice'))
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

    @app.route('/verify_notice')
    def verify_notice():
        return render_template('verify_notice.html')

    @app.route('/verify_email/<token>')
    def verify_email(token):
        try:
            email = s.loads(token, salt='email-confirm', max_age=3600)
            select_query = None
            db = g.get('db')

            if app.config['DB_TYPE'] == 'SQLITE':
                select_query = "SELECT * FROM USER WHERE email = ?"
            else:
                select_query = "SELECT * FROM USER WHERE email = %s"
            
            result = db.fetch_query(select_query, (email,))
            
            if result:
                # Assuming verification is successful if the email exists in the database
                return redirect(url_for('login', message='Verification successful! Please log in.'))
            else:
                return render_template('verify_email.html', message='Verification failed. User not found.')
        except SignatureExpired:
            return render_template('verify_email.html', message='The verification link has expired.')

    
    @socketio.on('connect')
    def handle_connect():
        print('Client Connected')

    @socketio.on('connect')
    def handle_connect():
        print('Client Connected')

    @socketio.on('user_join')
    def handle_user_join(data):
        try:
            print(f"Recepient Name-------> {data['recipient']}")
            print(f"Recepient Public Key-------> {data['email']}")
            # if 'recipient' not in data or 'publicKey' not in data:
            #     raise ValueError("Missing 'recipient' or 'publicKey' in data")

            recipient = data['recipient']
            # public_key = data['publicKey']

            print(f"User {recipient} Joined!")

            clientsSID[recipient] = request.sid
            clients[request.sid] = recipient
            # broadcastKeys[recipient] = public_key
            allClients[recipient] = data['email']

            emit("allUsers", {"allClients": allClients}, broadcast=True)
        
        except ValueError as ve:
            print(f"ValueError: {ve}")
            emit('error', {'message': str(ve)})
        
        except KeyError as ke:
            print(f"KeyError: {ke}")
            emit('error', {'message': 'An internal error occurred. Please try again later.'})
        
        except Exception as ex:
            print(f"Unexpected error: {ex}")
            emit('error', {'message': 'An unexpected error occurred. Please try again later.'})


    @socketio.on('send_email_notification')
    def handle_send_email_notification(data):
        try:
            recipient = data['recipient_name']
            if recipient in clientsSID:
                recipient_sid = clientsSID[recipient]
                print(f"Recepient Name: ------->>{recipient}")
                print(f"Recepient SID: ------->>{recipient_sid}")
                print(f"Sender: ------->>{clients[request.sid]}")
                emit('email_send_notify', {'nitification': data['notification'], 'sender': clients[request.sid]}, room=recipient_sid)
            else:
                print('Recipient not connected.')
        except Exception as ex:
            print(f"An error occurred: {ex}")

    @socketio.on('reply_email_notification')
    def handle_reply_email_notification(data):
        try:
            recipient = data['recipient_name']
            if recipient in clientsSID:
                recipient_sid = clientsSID[recipient]
                print(f"Recepient Name: ------->>{recipient}")
                print(f"Recepient SID: ------->>{recipient_sid}")
                print(f"Sender: ------->>{clients[request.sid]}")
                emit('email_reply_notify', {'nitification': data['notification'], 'sender': clients[request.sid]}, room=recipient_sid)
            else:
                print('Recipient not connected.')
        except Exception as ex:
            print(f"An error occurred: {ex}")


    @socketio.on('message')
    def handle_message(data):
        try:
            recipient = data['recipient_name']
            print("Recepient name: -------"+recipient)
            print("Recepient message: -------"+data['message'])
            if recipient in clientsSID:
                recipient_sid = clientsSID[recipient]
                print("Client: -------"+recipient_sid)
                emit('message', {'message': data['message'], 'sender': clients[request.sid]}, room=recipient_sid)
            else:
                print('Recipient not connected.')
        except Exception as ex:
            print(f"An error occurred: {ex}")


    @socketio.on('logout')
    def handle_logout(data):
        try:
            print(f"Logout Data : {data}")
            if request.sid in clients:
                user = clients[request.sid]
                print(f"logout user data : {user}")
                del clientsSID[user]
                del allClients[user]
                del clients[request.sid]

                emit("logoutUsers", {"logoutUser": user}, broadcast=True)

                print("User logging out !!!!")
                emit('logout_redirect', room=request.sid)
            else:
                print(f"Session ID {request.sid} not found in allClients dictionary")
        except KeyError as ke:
            print(f"KeyError: {ke}")
            emit('error', {'message': 'An internal error occurred. Please try again later.'}, room=request.sid)


    @app.route('/logout')
    def logout():
        session.pop('loggedin', None)
        session.pop('username', None)
        session.pop('profile', None) 
        session.pop('google_oauth_state', None)
        return redirect(url_for('login'))
    
    # Typing Indicator in the server side
    @socketio.on('typing')
    def handle_typing(data):
        try:
            #print(f"Typing event from {data['sender']} to {data['recipient']}")
            recipient = data['recipient']
            if recipient in clientsSID:
                recipient_sid = clientsSID[recipient]
                emit('typing', {'sender': clients[request.sid]}, room=recipient_sid)
        except Exception as ex:
            print(f"An error occurred: {ex}")

    @socketio.on('stop_typing')
    def handle_stop_typing(data):
        try:
            #print(f"Stop typing event from {data['sender']} to {data['recipient']}")
            recipient = data['recipient']
            if recipient in clientsSID:
                recipient_sid = clientsSID[recipient]
                emit('stop_typing', {'sender': clients[request.sid]}, room=recipient_sid)
        except Exception as ex:
            print(f"An error occurred: {ex}")



    # comminting following method, refer to the method defined earlier.
    #@app.teardown_appcontext
    #def teardown_db(exception):
    #    close_db()


    @app.route('/sendEmail', methods=['GET', 'POST'])
    def sendEmail():
        """Send an email from the application to get the email confirmation for registration and 
        other purposes. 
        """
        if request.method == 'POST':
            email = request.form['email']
            subject = request.form['subject']
            body = request.form['body']
            print(f"email : {email} - subject: {subject} - body : {body}")
            
            msg = Message(
                subject,
                recipients=[email]
            )
            msg.body = body
            mail.send(msg)
            flash('Email sent successfully!', 'success')
            return redirect(url_for('sendEmail'))

        return render_template('sendEmail.html')
    
    @app.route('/composeEmail', methods=['GET', 'POST'])
    def composeEmail():
        if request.method == 'POST':
            recipient = request.form.get('recipient')
            subject = request.form.get('subject')
            body = request.form.get('body')

            # Construct the mailto link
            mailto_link = f"mailto:{recipient}?subject={subject}&body={body}"
            return redirect(mailto_link)

        #return render_template(url_for('index'))
        return redirect(url_for('index'))

    return app

if __name__ == "__main__":
    app = create_app()
    socketio.run(app, host='0.0.0.0', port=8080, debug=True)