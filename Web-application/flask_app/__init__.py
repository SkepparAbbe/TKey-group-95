import os
import requests
import uuid
import time
import hashlib
from .verify import verify
import time

from .auth import load_logged_in_user, login_required, bp
import psycopg2.extras
from flask import Flask
from flask import g, render_template, redirect, url_for, request, session, jsonify

def create_app(test_config=None):
    # Create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flask.sqlite'),
        FLASK_RUN_HOST='localhost',
        FLASK_RUN_PORT=8000
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
    
    @app.before_request
    def start_timer():
        """Runs before each request to store start time."""
        g.start_time = time.time()

    @app.after_request
    def log_time(response):
        """Runs after each request to log execution time."""
        if hasattr(g, "start_time"):
            elapsed_time = time.time() - g.start_time
            print(f"⏳ Endpoint {request.path} took {elapsed_time:.4f} seconds")

        return response

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
        return render_template('index.html')
    
    @app.route('/challenge', methods=['POST'])
    def send_challenge():
        data = request.json
        username = data['username']
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
    def auth():
        data = request.json
        user_session = session.get(data['session_id'])
        username = user_session['username']
        challenge = user_session['challenge']
        signature = data['signature']
        db = database.get_db_connection()
        cursor = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute('SELECT * FROM "user" WHERE username=%s', (username,))
        user = cursor.fetchone()
        if not user:
            db.close()
            return jsonify({'error': 'invalid credentials'}), 401
        db.close()
        if not validate(challenge, signature, user['publickey']):
            return jsonify({'error': 'invalid credentials'}), 401
        session.clear()
        session['user_id'] = user['id']
        return jsonify({
            'success': 'Successfully logged in',
            'redirect_url': url_for('home')  # Or any other page you want to redirect to
        }), 200
    
    @app.route('/register', methods=['POST'])
    def register():
        data = request.json
        user_session = session.get(data['session_id'])
        username = user_session['username']
        challenge = user_session['challenge']
        signature = data['signature']
        public_key = data['publicKey']
        if validate(challenge, signature, public_key):
            conn = database.get_db_connection()
            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cursor.execute('SELECT * FROM "user" WHERE username=%s', (username,))
            user = cursor.fetchone()
            if user:
                return jsonify({'error': 'user already exists'}), 401
            cursor.execute("""
                         INSERT INTO "user" (username, publicKey)
                         VALUES (%s, %s)""", (username, public_key))
            conn.commit()
            conn.close()
        return jsonify({
            'success': 'Successfully registered user',
            'redirect_url': url_for('login')  # Or any other page you want to redirect to
        }), 200


    @app.route('/login', methods = ['GET'])
    def login():
        return render_template('login.html')
    

    @app.route('/register', methods = ['GET'])
    def register1():
        return render_template('register.html')

    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('index'))

    @app.route('/home')
    @login_required
    def home():
        # fetch the logged in user
        user = g.user
        return render_template('home.html', user=user)

    return app