import os
import requests
import uuid
import time
import hashlib
from .verify import verify

from .auth import load_logged_in_user, login_required, bp

from flask import Flask
from flask import g, render_template, redirect, url_for, request, session

def create_app(test_config=None):
    # Create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flask.sqlite')
    )

    if test_config is None:
        # load the instance config, if it exists when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # Load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass


    from . import db
    db.init_app(app)

    from . import auth
    app.register_blueprint(auth.bp)

    def generate_challenge():
        unique_id = uuid.uuid4().hex
        timestamp = int(time.time())
        challenge = f"{unique_id}-{timestamp}"
        return challenge
    
    def validate(msg: str, sig: str, key: str):
        return verify(msg, sig, key)
    
    def register_key():
        challenge = generate_challenge()
        response = requests.post("http://localhost:8081/registration", data=challenge)
        go_response = response.json()
        return [go_response, challenge]

    def send_challenge(challenge: str):
        response = requests.post("http://localhost:8081/login", data=challenge)
        go_response = response.json()
        return go_response

    # a simple page that says hello
    @app.route('/hello')
    def hello():
        return 'Hello world!' 

    @app.route('/')
    def index():
        return redirect(url_for('login'))
    
    @app.route('/login', methods = ['GET', 'POST'])
    def login():
        msg = ''
        if (request.method == 'POST' and 'username' in request.form):
            username = request.form['username']
            data = db.get_db()
            user = data.execute("SELECT * FROM user WHERE username=?", (username,)).fetchone()
            if user:
                public_key = user['publicKey']
                challenge = generate_challenge()
                response = send_challenge(challenge)
                if validate(challenge, response['signature'], public_key):
                    # authenticate & add user to session
                    # redirect(url_for('home'))
                    # TODO Swap this for the things above
                    session.clear()
                    session['user_id'] = user['id']
                    #session['username'] = user['username']
                    return redirect(url_for('home'))
                else:
                    msg = 'Signature couldn\'t be validated'
                pass
            else:
                msg = 'Invalid credentials'
            data.close()
        return render_template('login.html', msg=msg, success=False)

    @app.route('/register', methods = ['GET', 'POST'])
    def register():
        msg = ''
        success = False
        if (request.method == 'POST' and 'username' in request.form):
            username = request.form['username']
            data = db.get_db()
            user = data.execute("SELECT * FROM user WHERE username=?", (username,)).fetchone()
            if not user:
                response, challenge = register_key()
                if validate(challenge, response['signature'], response['publicKey']):
                    data.execute("""
                                 INSERT INTO user (username, publicKey)
                                 VALUES (?, ?)""", (username, response['publicKey']))
                    data.commit()
                    msg = 'Signature was succcessfully validated'
                    success = True
                else:
                    msg = 'Signature couldn\'t be validated'
            else:
                msg = 'A user with that name already exists'
            data.close()
        return render_template('register.html', msg=msg, success=success)
    
    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))

    @app.route('/home')
    @login_required
    def home():
        # fetch the logged in user
        user = g.user
        return render_template('home.html', user=user)

    return app