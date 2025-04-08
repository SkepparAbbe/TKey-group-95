import os
import uuid
import time
import hashlib
from .verify import verify
import time

from .auth import load_logged_in_user, login_required, bp
import psycopg2.extras
from flask import Flask
from flask import g, render_template, redirect, url_for, request, session, jsonify
from flask_session import Session
from redis.client import Redis
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, ValidationError
from flask_wtf.csrf import CSRFProtect, validate_csrf
from wtforms.validators import DataRequired


from .qrGen import generate_qr, verify_totp 

def create_app(test_config=None):
    # Create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = Redis(host='redis', port=6379)
    #DATABASE=os.environ.get('DATABASE_URL')
    app.config['SESSION_PERMANENT'] = False

    Session(app)



    # Creates csrf protection object that forms from flask-wtf needs.
    csrf = CSRFProtect(app)

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

    # a simple page that says hello
    @app.route('/hello')
    def hello():
        return 'Hello world!' 

    @app.route('/')
    def index():
        return render_template('index.html')
    
    class LoginForm(FlaskForm):
        username = StringField('Username',validators=[DataRequired(message="Username is required")])
        totp = StringField('TOTP',validators=[DataRequired(message="TOTP is required")])
        submit = SubmitField('Login')

    class RegisterForm(FlaskForm):
        username = StringField('Username',validators=[DataRequired(message="Username is required")])
        submit = SubmitField('Register')
    
    @app.route('/challenge', methods=['POST'])
    def send_challenge():
        if not csrf_handler(request):
            jsonify({'error': 'Invalid CSRF token'}), 400
        data = request.json
        username = data['username']
        challenge = generate_challenge()
        session['username'] = username
        session['challenge'] = challenge
        return jsonify({
            'challenge': challenge
        }), 200
    
    @app.route('/verify', methods=['POST'])
    def auth():
        data = request.json
        signature = data['signature']
        username = session.get('username')
        challenge = session.get('challenge')
        db = database.get_db_connection()
        cursor = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute('SELECT * FROM "user" WHERE username=%s', (username,))
        user = cursor.fetchone()
        if not user:
            db.close()
            return jsonify({'error': 'Invalid credentials'}), 401
        db.close()

        if 'totp' not in data:
            return jsonify({'error': 'TOTP code is required'}), 401

        if not validate(challenge, signature, user['publickey']):
            return jsonify({'error': 'Invalid credentials'}), 401
        session.clear()
        session['user_id'] = user['id']

        if not verify_totp(user['secret'], data['totp']):
            return jsonify({'error': 'Invalid TOTP code'}), 401

        return jsonify({
            'success': 'Successfully logged in',
            'redirect_url': url_for('home')  # Or any other page you want to redirect to
        }), 200
    
    def csrf_handler(request):
        csrf_token = request.headers.get('X-CSRFToken')
        try:
            validate_csrf(csrf_token)
        except Exception as e:
            return False
        return True
    
    @app.route('/register', methods=['POST'])
    def register():
        if not csrf_handler(request):
            jsonify({'error': 'Invalid CSRF token'}), 400
        data = request.json
        signature = data['signature']
        username = session.get('username')
        challenge = session.get('challenge')
        public_key = data['publicKey']
        if validate(challenge, signature, public_key):
            conn = database.get_db_connection()
            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cursor.execute('SELECT * FROM "user" WHERE username=%s', (username,))
            user = cursor.fetchone()
            if user:
                return jsonify({'error': 'User already exists'}), 401
            img_str, secret = generate_qr(username) #generate qr code and secret

            session['p_register'] = {
                'username': username,
                'public_key': public_key,
                'secret': secret,
                'qr_code': img_str
            }
            conn.close()
            return jsonify({
                'success': 'Successfully registered',
                'redirect_url': url_for('show_qr')  # Or any other page you want to redirect to
            }), 200
        return jsonify({'error': 'Invalid credentials'}), 401
    
    @app.route('/confirm-totp', methods=['POST'])
    def confirm_totp():
        if not csrf_handler(request):
            jsonify({'error': 'Invalid CSRF token'}), 400
        p_data = session.get('p_register')
        if not p_data:
            return redirect(url_for('index'))
        totp_code = request.form.get('totp')
        if verify_totp(p_data['secret'], totp_code):
            conn = database.get_db_connection()
            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cursor.execute("""
                        INSERT INTO "user" (username, publickey,secret)
                        VALUES (%s, %s,%s)""", (p_data['username'], p_data['public_key'], p_data['secret']))
            conn.commit()
            conn.close()
            session.pop('p_register', None)
            return redirect(url_for('login'))
        else:
            return render_template('register_qr.html', qr_code=p_data['qr_code'], error='Invalid TOTP code')

    @app.route('/show-qr')
    def show_qr():
        p_data = session.get('p_register')
        if not p_data:
            return redirect(url_for('index'))
        return render_template('register_qr.html', qr_code=p_data['qr_code'])

    @app.route('/login', methods = ['GET'])
    def login():
        form = LoginForm()
        return render_template('login.html', form=form)
    
    @app.route('/register', methods = ['GET'])
    def register1():
        form = RegisterForm()
        return render_template('register.html', form=form)

    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('index'))
    
    @app.route('/delete')
    @login_required
    def delete():
        uid = session['user_id']
        conn = database.get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute('DELETE FROM "user" WHERE id=%s', (uid,))
        conn.commit()
        conn.close()
        session.clear()
        return redirect(url_for('index'))

    @app.route('/home')
    @login_required
    def home():
        # fetch the logged in user
        user = g.user
        return render_template('home.html', user=user)

    return app