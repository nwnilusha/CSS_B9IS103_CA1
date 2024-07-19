import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    #SECRET_KEY = os.getenv('SECRET_KEY')
    #MYSQL_USER = os.getenv('MYSQL_USER')
    #MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD')
    #MYSQL_HOST = os.getenv('MYSQL_HOST')
    #MYSQL_DB = os.getenv('MYSQL_DB')
    #GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
    #GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')

    SECRET_KEY = "ABCD1234"
    MYSQL_USER = "dbs"
    MYSQL_PASSWORD = "password"
    MYSQL_HOST = "localhost"
    MYSQL_DB = "GOBUZZ"
    GOOGLE_CLIENT_ID = '484213283363-0lr7vmgdk81h02f8e9p8pgalq1n9ov6v.apps.googleusercontent.com'
    GOOGLE_CLIENT_SECRET = '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'

