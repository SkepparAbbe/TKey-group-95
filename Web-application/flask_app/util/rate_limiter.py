from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import session


limiter = Limiter(
    key_func = get_remote_address,
    storage_uri="redis://redis:6379",
    storage_options={"socket_connect_timeout": 30},
    default_limits = []
)

def ip_and_account():
    ip = get_remote_address()
    account = session.get('username')
    return f"{ip}:{account}"

def requested_user():
    user = session.get('p_recover')['username']
    return f"{user}"

def ip_and_account2():
    ip = get_remote_address()
    account = session.get('username')
    return f"{ip}:{account}"