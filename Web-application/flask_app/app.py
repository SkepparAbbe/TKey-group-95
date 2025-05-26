import os
import uuid
import time
import hashlib
import time

import psycopg2.extras
from flask import Flask
from flask import g, render_template, redirect, url_for, request, session, jsonify
from flask_limiter.errors import RateLimitExceeded
from flask_session import Session
from redis.client import Redis
from flask_wtf.csrf import CSRFProtect, validate_csrf

from .forms import *

from .auth import auth_bp
from .util import auth2
from .util import database
from .util.rate_limiter import limiter

def create_app():

    redis_client = Redis(host='redis', port=6379)
    app = Flask(__name__, instance_relative_config=True)
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = redis_client
    app.config['SESSION_PERMANENT'] = False
    app.config['RATELIMIT_ENABLED'] = True

    Session(app)

    limiter.init_app(app)

    @app.errorhandler(RateLimitExceeded)
    def ratelimit_handler(e):
        return jsonify({'error': 'Rate limit reached'}), 429

    csrf = CSRFProtect(app)

    database.init_app(app)

    app.register_blueprint(auth2.bp)
    app.register_blueprint(auth_bp)

    def generate_challenge():
        unique_id = uuid.uuid4().hex
        timestamp = int(time.time())
        challenge = f"{unique_id}-{timestamp}"
        return challenge

    def csrf_handler(request):
        if request.is_json:
            csrf_token = request.headers.get('X-CSRFToken')
        else:   # most likely doesn't need the else-part
            csrf_token = request.form.get('csrf_token')
        try:
            validate_csrf(csrf_token)
        except Exception as e:
            return False
        return True

    @app.after_request
    def add_no_cache_headers(response):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    
    @app.before_request
    def before_any_request():
        if request.method == 'POST':
            if not csrf_handler(request):
                return jsonify({'error': 'Invalid CSRF token'}), 403

    @app.route('/', methods=['GET'])
    def index():
        return render_template('index.html')
    
    @app.route('/challenge', methods=['POST'])
    def send_challenge():
        if not csrf_handler(request):
            return jsonify({'error': 'Invalid CSRF token'}), 403
        challenge = generate_challenge()
        session['challenge'] = challenge
        return jsonify({
            'challenge': challenge
        }), 200
    
    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('index'))
    
    @app.route('/delete', methods = ['GET'])
    @auth2.login_required
    def delete():
        uid = session['uid']
        conn = database.get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute('DELETE FROM "user" WHERE id=%s', (uid,))
        conn.commit()
        conn.close()
        session.clear()
        return redirect(url_for('index'))
        
    @app.route('/home')
    @auth2.login_required
    def home():
        # fetch the logged in user
        user = g.user
        return render_template('home.html', user=user)

    return app