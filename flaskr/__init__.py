from flask import Flask, render_template, g, jsonify
from . import db
from flask import request, session, redirect, url_for
import secrets
import json
import string
import logging
from .db import get_db
from flask_bcrypt import Bcrypt
from flask_bcrypt import check_password_hash

def generate_secret_key(length=32):
    alphabet = string.ascii_letters + string.digits + '!@#$%^&*()-=_+'
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = generate_secret_key()

    app.config['MYSQL_HOST'] = 'localhost'
    app.config['MYSQL_USER'] = 'root'
    app.config['MYSQL_PASSWORD'] = 'password'
    app.config['MYSQL_DB'] = 'GOBUZZ'

users = {}
userKeys = {}
broadcastKeys = {}


app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = generate_secret_key()
# socketio = SocketIO(app)

@app.route('/index')
def index():
    # Replace with actual logic for your index page
    return render_template('index.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT username FROM User WHERE username=%s AND password=%s', (username, password))
        record = cursor.fetchone()
        cursor.close()

        if record:
            session['loggedin'] = True
            session['username'] = username
            return redirect(url_for('index'))  # Redirect to your index page or any other page
        else:
            msg = 'Incorrect Username or Password'
            return render_template('login.html', msg=msg)
    else:
        return render_template('login.html')

@app.route('/goBackToLogin', methods=['GET', 'POST'])
def goBackToLogin():
    return render_template('login.html')




@app.route('/signup', methods=['GET'])
def signup():
    return render_template('signup.html')

@app.teardown_appcontext
def close_db(error):
    db.close_db()

    return app

if __name__ == "__main__":
    app.run(host='0.0.0.0', port='8080')