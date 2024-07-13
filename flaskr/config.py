# application configuration file
# This file used to overide the default configurations.
# Add all your configurations to here.

from dotenv import load_dotenv
import os

load_dotenv()

class Config:
    SECRET_KEY = "ABCD1234"
    MYSQL_USER = "dbs"
    MYSQL_PASSWORD = "password"
    MYSQL_HOST = "localhost"
    MYSQL_DB = "GOBUZZ"
    GOOGLE_CLIENT_ID = '484213283363-0lr7vmgdk81h02f8e9p8pgalq1n9ov6v.apps.googleusercontent.com'
    GOOGLE_CLIENT_SECRET = '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'

    # mail server configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    #MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    #MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_USERNAME = "gobuzzchat@gmail.com"
    MAIL_PASSWORD = "rluv cdwn crxv nahm"
    MAIL_DEFAULT_SENDER = ('Go Buzz', 'gobuzzchat@gmail.com')

    
