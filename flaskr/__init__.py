from flask import Flask, render_template

def create_app():
    app = Flask(__name__)

    @app.route("/")#URL leading to method
    def index():
       return render_template('index.html')

    return app

if __name__ == "__main__":
 app.run(host='0.0.0.0', port='8080') # indent this line