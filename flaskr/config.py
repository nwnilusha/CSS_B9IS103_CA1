import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    SECRET_KEY = "ABCD1234"
    MYSQL_USER = "dbs"
    MYSQL_PASSWORD = "password"
    MYSQL_HOST = "localhost"
    MYSQL_DB = "GOBUZZ"
    GOOGLE_CLIENT_ID = '484213283363-0lr7vmgdk81h02f8e9p8pgalq1n9ov6v.apps.googleusercontent.com'
    GOOGLE_CLIENT_SECRET = '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'
