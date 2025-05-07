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

from .recovery import generate_mnemonic, convert_to_seed, hash_seed, verify_mnemonic

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

    from . import database
    database.init_app(app)

    from . import auth
    app.register_blueprint(auth.bp)
    
    class LoginForm(FlaskForm):
        username = StringField('Username',validators=[DataRequired(message="Username is required")])
        totp = StringField('TOTP',validators=[DataRequired(message="TOTP is required")])
        submit = SubmitField('Login')

    class RegisterForm(FlaskForm):
        username = StringField('Username',validators=[DataRequired(message="Username is required")])
        submit = SubmitField('Register')

    class TOTPForm(FlaskForm):
        totp = StringField('TOTP',validators=[DataRequired(message="TOTP is required")])
        submit = SubmitField('Verify')
    
    class RecoveryForm(FlaskForm):
        username = StringField('Username',validators=[DataRequired(message="Username is required")])
        submit = SubmitField('Recover')

    def generate_challenge():
        unique_id = uuid.uuid4().hex
        timestamp = int(time.time())
        challenge = f"{unique_id}-{timestamp}"
        return challenge
    
    def validate(msg: str, sig: str, key: str):
        return verify(msg, sig, key)

    def csrf_handler(request):
        if request.is_json:
            csrf_token = request.headers.get('X-CSRFToken')
        else:
            csrf_token = request.form.get('csrf_token')
        try:
            validate_csrf(csrf_token)
        except Exception as e:
            return False
        return True


    @app.route('/', methods=['GET'])
    def index():
        return render_template('index.html')
    

    @app.route('/challenge', methods=['POST'])
    def send_challenge():
        if not csrf_handler(request):
            return jsonify({'error': 'Invalid CSRF token'}), 403
        data = request.json
        challenge = generate_challenge()
        session['username'] = data['username']
        session['challenge'] = challenge
        return jsonify({
            'challenge': challenge
        }), 200
    

    @app.route('/verify', methods=['POST'])
    def auth():
        if not csrf_handler(request):
            return jsonify({'error': 'Invalid CSRF token'}), 403
        data = request.json
        signature = data['signature']
        totp = data.get('totp')
        username = session.get('username')
        challenge = session.get('challenge')
        db = database.get_db_connection()
        cursor = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute('SELECT * FROM "user" WHERE username=%s', (username,))
        user = cursor.fetchone()
        db.close()

        if not user or not validate(challenge, signature, user['publickey']):
            return jsonify({'error': 'Invalid credentials'}), 401
        if not totp or not verify_totp(user['secret'], totp):
            return jsonify({'error': 'Invalid TOTP code'}), 401
        
        session.clear()
        session['uid'] = user['id']

        return jsonify({
            'success': 'Successfully logged in',
            'redirect_url': url_for('home')
        }), 200
    

    @app.route('/register', methods=['POST'])
    def register():
        if not csrf_handler(request):
            return jsonify({'error': 'Invalid CSRF token'}), 403
        data = request.json
        signature = data['signature']
        username = session.get('username')
        challenge = session.get('challenge')
        public_key = data['publicKey']
        if validate(challenge, signature, public_key):
            db = database.get_db_connection()
            cursor = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cursor.execute('SELECT * FROM "user" WHERE username=%s', (username,))
            user = cursor.fetchone()
            cursor.execute('SELECT * FROM "user" WHERE publickey=%s', (public_key,))
            pkey = cursor.fetchone()
            db.close()

            if user:
                return jsonify({'error': 'User already exists'}), 401
            if pkey:
                return jsonify({'error': 'TKey already registered'}), 401
            
            img_str, secret = generate_qr(username)

            session['pub_key'] = public_key
            session['secret'] = secret
            session['qr_code'] = img_str

            return jsonify({
                'success': 'Successfully registered',
                'redirect_url': url_for('show_qr')
            }), 200
        return jsonify({'error': 'Invalid credentials'}), 401
    
    
    @app.route('/confirm-totp', methods=['POST'])
    def confirm_totp():
        if not csrf_handler(request):
            return jsonify({'error': 'Invalid CSRF token'}), 403
        #p_data = session.get('p_register')
        #if not p_data:
        #    return redirect(url_for('index'))
        totp_code = request.form.get('totp')
        if verify_totp(session.get('secret'), totp_code):
            mnemonic = generate_mnemonic()
            hash_, salt = hash_seed(convert_to_seed(mnemonic))
            
            session['mnemonic'] = mnemonic
            session['salt'] = salt
            session['hash'] = hash_

            return redirect(url_for('show_mnemonic'))
        else:
            return render_template('register_qr.html', qr_code=session['qr_code'], error='Invalid TOTP code')


    @app.route('/show-mnemonic', methods=['GET'])
    def show_mnemonic():
        mnemonic = session.get('mnemonic')
        if not mnemonic:
            return redirect(url_for('index'))

        mnemonic_words = mnemonic.split()
        
        return render_template('register_mnemonic.html', mnemonic_words=mnemonic_words, error=None)


    @app.route('/finalize-account', methods=['POST'])
    def finalize_account():
        if not csrf_handler(request):
            return jsonify({'error': 'Invalid CSRF token'}), 403
        
        db = database.get_db_connection()
        cursor = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute("""
            INSERT INTO "user" (username, publickey, secret, salt, hash) VALUES (%s, %s, %s, %s, %s)""",
            (session['username'], session['pub_key'], session['secret'], session['salt'], session['hash']))
        db.commit()
        db.close()

        session.clear()
        return redirect(url_for('login'))


    @app.route('/show-qr', methods=['GET'])
    def show_qr():
        qr = session.get('qr_code')
        if not qr:
            return redirect(url_for('index'))
        form = TOTPForm()
        return render_template('register_qr.html', form=form, qr_code=qr, error=None)


    @app.route('/login', methods = ['GET'])
    def login():
        form = LoginForm()
        return render_template('login.html', form=form)
    

    @app.route('/recover', methods=['GET'])
    def recover():
        form = RecoveryForm()
        return render_template('recover.html', form=form)
    

    @app.route('/register', methods = ['GET'])
    def register_():
        form = RegisterForm()
        return render_template('register.html', form=form)
    

    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('index'))
    

    @app.route('/delete', methods = ['GET'])
    @login_required
    def delete():
        uid = session['uid']
        conn = database.get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute('DELETE FROM "user" WHERE id=%s', (uid,))
        conn.commit()
        conn.close()
        session.clear()
        return redirect(url_for('index'))


    @app.route('/recover-user', methods=['POST'])
    def recover_user():
        if not csrf_handler(request):
            return jsonify({'error': 'Invalid CSRF token'}), 403
        data = request.json
        if not data or 'username' not in data:
            return jsonify({'error': 'Username is required'}), 400

        username = data['username']

        db = database.get_db_connection()
        cursor = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute('SELECT * FROM "user" WHERE username=%s', (username,))
        user = cursor.fetchone()
        db.close()

        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        session.clear()
        session['username'] = username
        session['mnemonic_pass'] = False

        return jsonify({'success': 'User found'}), 200


    @app.route('/recover-mnemonic', methods=['POST'])
    def recover_mnemonic():
        if not csrf_handler(request):
            return jsonify({'error': 'Invalid CSRF token'}), 403
    
        data = request.json
        username = session['username']
        mnemonic = " ".join(data[f"word{i}"] for i in range(1, 13))

        db = database.get_db_connection()
        cursor = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute('SELECT * FROM "user" WHERE username=%s', (username,))
        user = cursor.fetchone()
        db.close()
        
        if not verify_mnemonic(user['hash'], user['salt'], mnemonic):
            return jsonify({'error': 'Wrong phrase'}), 404
        session['mnemonic_pass'] = True
        return jsonify({'success': 'Mnemonic verified'}), 200


    #@app.route('/recover-challenge-generate', methods=['POST'])
    #def recover_challenge_generate():
    #    if not csrf_handler(request):
    #        jsonify({'error': 'Invalid CSRF token'}), 400
    #
    #    #get from previous session username
    #    p_recover = session.get('p_recover')
    #    if not p_recover:
    #        return jsonify({'error': 'Session expired'}), 400
    #
    #    if not p_recover['pass']:
    #        return jsonify({'error': 'Mnemonic not verified'}), 400
    #
    #    session_id = str(uuid.uuid4())
    #    challenge = generate_challenge()
    #    session[session_id] = {
    #        'username': p_recover['username'],
    #        'challenge': challenge
    #    }
    #    return jsonify({
    #        'session_id': session_id,
    #        'challenge': challenge
    #    }), 200

    @app.route('/recover-challenge', methods=['POST'])
    def recover_challenge():
        if not csrf_handler(request):
            return jsonify({'error': 'Invalid CSRF token'}), 403
        if not session.get('mnemonic_pass'):
            return jsonify({'error': 'Invalid recovery token'}), 400

        data = request.json

        username = session['username']
        challenge = session['challenge']
        signature = data['signature']
        public_key = data['publicKey']

        if validate(challenge, signature, public_key):
            
            db = database.get_db_connection()
            cursor = db.cursor()
            cursor.execute('SELECT username FROM "user" WHERE publickey = %s AND username != %s',
                          (public_key, username))
            existing = cursor.fetchone()

            if existing:
                db.close()
                return jsonify({'error': 'This TKey is already in use by another account'}), 409
            
            cursor.execute('UPDATE "user" SET publickey = %s WHERE username = %s', (public_key, username))
            db.commit()
            db.close()

            session.clear()
            return jsonify({
                'success': 'Successfully recoverered',
            }), 200
        return jsonify({'error': 'Invalid credentials'}), 401

    @app.route('/home')
    @login_required
    def home():
        # fetch the logged in user
        user = g.user
        return render_template('home.html', user=user)

    return app
