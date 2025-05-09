from flask import render_template, request, url_for, session, jsonify, redirect
import psycopg2.extras

from . import auth_bp

from ..util.verify import verify
from ..util.recovery import verify_mnemonic
from ..forms import RecoveryForm, MnemonicForm, RecoveryChallengeForm
from ..util import database


@auth_bp.route('/recover', methods=['GET', 'POST'])
def recover():
	if request.method == 'GET':
		form = RecoveryForm()
		return render_template('recover.html', form=form)

	username = request.json['username']
	db = database.get_db_connection()
	cursor = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
	cursor.execute('SELECT * FROM "user" WHERE username=%s', (username,))
	user = cursor.fetchone()
	db.close()

	if not user:
		return jsonify({'error': 'No user found'}), 400
	
	session.clear()
	session['username'] = username
	session['mnemonic_pass'] = False

	return jsonify({'redirect_url': url_for('auth.mnemonic')}), 200

@auth_bp.route('/recover/mnemonic', methods=['GET', 'POST'])
def mnemonic():
	if request.method == 'GET':
		mnemonic_token = session.get('mnemonic_pass', None)
		if mnemonic_token is None:
			return redirect(url_for('auth.recover'))
		form = MnemonicForm()
		return render_template('recover_mnemonic.html', form=form)

	data = request.json
	username = session['username']
	mnemonic = " ".join(data[f"word{i}"] for i in range(1, 13))

	db = database.get_db_connection()
	cursor = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
	cursor.execute('SELECT * FROM "user" WHERE username=%s', (username,))
	user = cursor.fetchone()
	db.close()
	
	if not verify_mnemonic(user['hash'], user['salt'], mnemonic):
		return jsonify({'error': 'Wrong mnemonic phrase'}), 404
	session['mnemonic_pass'] = True
	return jsonify({'redirect_url': url_for('auth.keyRecovery')}), 200
    
@auth_bp.route('/recover/verify', methods=['GET', 'POST'])
def keyRecovery():
    if request.method == 'GET':
        mnemonic_token = session.get('mnemonic_pass', None)
        if not mnemonic_token:
            return redirect(url_for('auth.recover'))
        form = RecoveryChallengeForm()
        return render_template('recover_verify.html', form=form)
    
    if not session.get('mnemonic_pass'):
        return jsonify({'error': 'Invalid recovery token'}), 400

    data = request.json

    username = session['username']
    challenge = session['challenge']
    signature = data['signature']
    public_key = data['publicKey']

    if verify(challenge, signature, public_key):
        
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
            'redirect_url': url_for('auth.login')
        }), 200
    return jsonify({'error': 'Invalid credentials'}), 401