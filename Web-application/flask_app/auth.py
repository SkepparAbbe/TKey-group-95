import functools
from flask import g, Blueprint, redirect, url_for, session
import psycopg2.extras

from .database import get_db, get_db_connection

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('uid')
    if user_id is None:
        g.user = None
    else:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(
            'SELECT username FROM "user" WHERE id = %s', (user_id,)
        )
        user = cursor.fetchone()
        conn.close()
        if user is None:
            pass
        else:
            g.user = user['username']
        

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('login'))
        
        return view(**kwargs) 
    
    return wrapped_view