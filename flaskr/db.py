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

