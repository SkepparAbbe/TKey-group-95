from flask import render_template, request, url_for, session, jsonify, redirect
import psycopg2.extras

from . import auth_bp

from ..util.verify import verify
from ..util.qrGen import verify_totp, generate_qr
from ..util.recovery import generate_mnemonic, hash_seed, convert_to_seed
from ..forms import RegisterForm, TOTPForm, FinalizeForm
from ..util import database


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        form = RegisterForm()
        return render_template('register.html', form=form)

    data = request.json
    signature = data.get('signature')
    username = data.get('username')
    challenge = session.get('challenge')
    public_key = data.get('publicKey')
    if verify(challenge, signature, public_key):
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

        session['username'] = username
        session['pub_key'] = public_key
        session['secret'] = secret
        session['qr_code'] = img_str

        return jsonify({
            'success': 'Successfully registered',
            'redirect_url': url_for('auth.twofactor')
        }), 200
    return jsonify({'error': 'Invalid credentials'}), 401

@auth_bp.route('/register/twofactor', methods=['GET', 'POST'])
def twofactor():
    if request.method == 'GET':
        qr = session.get('qr_code')
        if not qr:
            return redirect(url_for('auth.register'))
        form = TOTPForm()
        return render_template('register_qr.html', form=form, qr_code=qr)
    
    totp_code = request.json.get('totp')
    if verify_totp(session.get('secret'), totp_code):
        mnemonic = generate_mnemonic()
        hash_, salt = hash_seed(convert_to_seed(mnemonic))
        
        session['mnemonic'] = mnemonic
        session['salt'] = salt
        session['hash'] = hash_

        return jsonify({'redirect_url': url_for('auth.finalize')}), 200
    return jsonify({'error': 'Invalid TOTP code'}), 401 

@auth_bp.route('/register/finalize', methods=['GET', 'POST'])
def finalize():
    if request.method == 'GET':
        mnemonic = session.get('mnemonic')
        if not mnemonic:
            return redirect(url_for('auth.register'))
        mnemonic_words = mnemonic.split()
        form = FinalizeForm()
        return render_template('register_mnemonic.html', mnemonic_words=mnemonic_words, form=form)

    db = database.get_db_connection()
    cursor = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute("""
        INSERT INTO "user" (username, publickey, secret, salt, hash) VALUES (%s, %s, %s, %s, %s)""",
        (session['username'], session['pub_key'], session['secret'], session['salt'], session['hash']))
    db.commit()
    db.close()

    session.clear()
    return jsonify({'redirect_url': url_for('auth.login')}), 200