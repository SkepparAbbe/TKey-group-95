import os
import requests
import uuid
import time
import hashlib
from .verify import verify

from flask import Flask
from flask import render_template, redirect, url_for, request, session, jsonify

def create_app(test_config=None):
    # Create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flask.sqlite'),
        FLASK_RUN_HOST='localhost',
        FLASK_RUN_PORT=5000
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


    from . import database
    database.init_app(app)

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

    #def send_challenge(challenge: str):
    #    response = requests.post("http://localhost:8081/login", data=challenge)
    #    go_response = response.json()
    #    return go_response

    # a simple page that says hello
    @app.route('/hello')
    def hello():
        return 'Hello world!' 

    @app.route('/')
    def index():
        return redirect(url_for('login'))
    
    @app.route('/challenge', methods=['POST'])
    def send_challenge():
        data = request.json
        username = data['username']
        #db = database.get_db()
        #user = db.execute('SELECT * FROM user WHERE username=?', (username,)).fetchone()
        #db.close()
        #if not user:
        #    return jsonify({'error': 'User not found'}), 404
        session_id = str(uuid.uuid4())
        challenge = generate_challenge()
        session[session_id] = {
            'username': username,
            'challenge': challenge
        }
        return jsonify({
            'session_id': session_id,
            'challenge': challenge
        }), 200
    
    @app.route('/verify', methods=['POST'])
    def verify1():
        data = request.json
        user_session = session.get(data['session_id'])
        username = user_session['username']
        challenge = user_session['challenge']
        signature = data['signature']
        db = database.get_db()
        user = db.execute('SELECT * FROM user WHERE username=?', (username,)).fetchone()
        db.close()
        print(challenge)
        print(signature)
        print(user['publicKey'])
        #challenge = "4a62d635cae241f88d501dfe66e6d1a3-1741047907"
        #signature = "UiHrwMiJ+vU+Zx4B3oRfeOHE/YtNMSSSCi8y1AgBm3kFHHqwgiwOX2N/m810tsO2Hsn2I2O1oWzHVH93/D2VCQ=="
        #pub = "kvQPmNx6b5ZsQ9Cwv/35+YYxyGbFz9fvns3IXrZyI3Y="
        if not validate(challenge, signature, user['publicKey']):
            return jsonify({'error': 'invalid credentials'}), 401
        return jsonify({'success': 'successfully logged in'}), 200 #todo, send auth-cookie
    
    @app.route('/register', methods=['POST'])
    def register():
        data = request.json
        user_session = session.get(data['session_id'])
        username = user_session['username']
        challenge = user_session['challenge']
        signature = data['signature']
        public_key = data['publicKey']
        print(challenge)
        print(signature)
        print(public_key)
        db = database.get_db()
        user = db.execute('SELECT * FROM user WHERE username=?', (username,)).fetchone()
        if validate(challenge, signature, public_key):
            print("Success!!!!")
        else:
            print("Fail!!!")


    @app.route('/login', methods = ['GET', 'POST'])
    def login():
        msg = ''
        #if (request.method == 'POST' and 'username' in request.form):
        #    username = request.form['username']
        #    data = database.get_db()
        #    user = data.execute("SELECT * FROM user WHERE username=?", (username,)).fetchone()
        #    if user:
        #        public_key = user['publicKey']
        #        challenge = generate_challenge()
        #        response = send_challenge(challenge)
        #        if validate(challenge, response['signature'], public_key):
        #            # authenticate & add user to session
        #            # redirect(url_for('home'))
        #            # TODO Swap this for the things above
        #            msg = 'Successfully logged in!'
        #        else:
        #            msg = 'Signature couldn\'t be validated'
        #        pass
        #    else:
        #        msg = 'Invalid credentials'
        #    data.close()
        return render_template('login.html', msg=msg, success=False)
    

    @app.route('/register', methods = ['GET'])
    def register1():
        msg = ''
        success = False
        #if (request.method == 'POST' and 'username' in request.form):
        #    username = request.form['username']
        #    data = database.get_db()
        #    user = data.execute("SELECT * FROM user WHERE username=?", (username,)).fetchone()
        #    if not user:
        #        response, challenge = register_key()
        #        if validate(challenge, response['signature'], response['publicKey']):
        #            data.execute("""
        #                         INSERT INTO user (username, publicKey)
        #                         VALUES (?, ?)""", (username, response['publicKey']))
        #            data.commit()
        #            msg = 'Signature was succcessfully validated'
        #            success = True
        #        else:
        #            msg = 'Signature couldn\'t be validated'
        #    else:
        #        msg = 'A user with that name already exists'
        #    data.close()
        return render_template('register.html', msg=msg, success=success)

    @app.route('/home')
    def home():
        # fetch the logged in user
        user = "Placeholder"
        return render_template('index.html', user=user)

    return app