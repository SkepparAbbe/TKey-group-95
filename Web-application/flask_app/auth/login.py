from flask import render_template, request, url_for, session, jsonify
import psycopg2.extras

from . import auth_bp

from ..util.verify import verify
from ..util.qrGen import verify_totp
from ..forms import LoginForm
from ..util import database


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        form = LoginForm()
        return render_template('login.html', form=form)
    
    #if not csrf_handler(request):
    #    return jsonify({'error': 'Invalid CSRF token'}), 403
    data = request.json
    signature = data['signature']
    totp = data.get('totp')
    username = data.get('username')
    challenge = session.get('challenge')
    db = database.get_db_connection()
    cursor = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('SELECT * FROM "user" WHERE username=%s', (username,))
    user = cursor.fetchone()
    db.close()

    if not user or not verify(challenge, signature, user['publickey']):
        return jsonify({'error': 'Invalid credentials'}), 401
    if not totp or not verify_totp(user['secret'], totp):
        return jsonify({'error': 'Invalid TOTP code'}), 401
    
    session.clear()
    session['uid'] = user['id']

    return jsonify({
        'success': 'Successfully logged in',
        'redirect_url': url_for('home')
    }), 200