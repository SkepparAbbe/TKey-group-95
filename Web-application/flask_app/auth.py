import functools
from flask import g, Blueprint, redirect, url_for, session
from .db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        user = get_db().execute(
            'SELECT username FROM user WHERE id = ?', (user_id,)
        ).fetchone()
        g.user = user['username'] 

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('login'))
        
        return view(**kwargs) 
    
    return wrapped_view