'''import mysql.connector
from flask import g, current_app
import click

HOST = 'localhost'
USER = 'root'
PASSWORD = 'password'
DATABASE = 'GOBUZZ'

def get_db():
    if 'db' not in g:
        g.db = mysql.connector.connect(
            host=HOST,
            user=USER,
            password=PASSWORD,
            database=DATABASE,
            autocommit=True
        )
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    with current_app.open_resource('schema.sql') as f:
        db.cursor().executescript(f.read().decode('utf8'))

def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)

@click.command('init-db')
def init_db_command():
    """Clear existing data and create new tables."""
    init_db()
    click.echo('Initialized the database.')
'''


import mysql.connector
from mysql.connector import Error
# import sqlite database libraries
import sqlite3
from flask import g, current_app
# Database class for SqLite
class DatabaseSQLite:
    def __init__(self, database_path=None):
        if database_path is None:
            database_path = current_app.config['DATABASE']
        self.database_path = database_path

    def connect(self):
        """Connects to the specific database."""
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_db(self):
        """Opens a new database connection if there is none yet for the current application context."""
        if not hasattr(g, 'sqlite_db'):
            g.sqlite_db = self.connect()
        return g.sqlite_db

    def close_db(self, error=None):
        """Closes the database again at the end of the request."""
        if hasattr(g, 'sqlite_db'):
            g.sqlite_db.close()

    def execute_vquery(self, query, params=()):
        """Execute an insert or update query"""
        db = self.get_db()
        cursor = db.cursor()
        try:
            cursor.execute(query, params)
            db.commit()
            return cursor.lastrowid
        except sqlite3.Error as er:
            print(f"DB query execution failure: {er}")
            db.rollback()
            raise
        finally:
            cursor.close()

    def disconnect(self):
        """Disconnect the already initialized database connection"""
        self.close_db()
        print("Database connection is disconnected")

    def fetch_query(self, query, params=()):
        """Execute a select query and return the result"""
        db = self.get_db()
        cursor = db.cursor()
        try:
            cursor.execute(query, params)
            result = cursor.fetchall()
            for row in result:
                print(f"data-> {row}")
            return [dict(row) for row in result]
        except sqlite3.Error as er:
            print(f"DB query execution failure: {er}")
            return None
        finally:
            cursor.close()


# Database class for mysql connectivity
class Database:
    def __init__(self, config):
        self.config = config
        self.connection = None
    
    def connect(self):
        """Initialize the database connection"""
        try:
            self.connection = mysql.connector.connect(**self.config)
            if self.connection.is_connected():
                print("Connected to MySQL database")
            else:
                selef.connection = None
        except Error as er:
            print(f"Error occurred while connecting to MySQL database: {er}")
            self.connection = None
    
    def disconnect(self):
        """Disconnect the already initialized database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("Database connection is disconnected")
    
    def ensure_connection(self):
        """Ensure the database connection is established"""
        if not self.connection or not self.connection.is_connected():
            self.connect()
            if not self.connection:
                raise Exception("Failed to establish a database connection")
    
    def execute_query(self, query, params=None):
        """Execute a database query
        Arguments:
        query: database query to execute
        params: parameters for the db query
        """
        self.ensure_connection()
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, params)
                self.connection.commit()
                return True
        except Error as er:
            print(f"DB query execution failure: {er}")
            self.connection.rollback()
            raise
    
    def execute_vquery(self, query, *params):
        """Execute a database query with variable arguments
        Arguments:
        query: database query to execute
        params: parameters for the db query
        """
        self.ensure_connection()
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, params)
                self.connection.commit()
                return True
        except Error as er:
            print(f"DB query execution failure: {er}")
            self.connection.rollback()
            raise
    
    def fetch_query(self, query, params=None):
        """Execute a database query and return the result set as a dictionary
        Arguments:
        query: database query
        params: parameters for the db query
        """
        self.ensure_connection()
        try:
            with self.connection.cursor(dictionary=True) as cursor:
                cursor.execute(query, params)
                result = cursor.fetchall()
                return result
        except Error as er:
            print(f"DB query execution failure: {er}")
            return None
    
    def insert_query(self, query, params):
        """Insert records into the database
        Arguments:
        query: database insert query
        params: parameters for the insert query
        """
        return self.execute_query(query, params)

