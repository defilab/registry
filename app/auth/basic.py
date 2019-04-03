from flask import request
from ..exception import InvalidAuthorizationHeader, BasicAuthFailed

def verify(username, password):
    return username == 'admin' and password == 'secret'

def check_basic():
    auth = request.authorization
    if not auth:
        raise InvalidAuthorizationHeader()
    if not verify(auth.username, auth.password):
        raise BasicAuthFailed()
    return True

def basic_auth(fn):
    @wraps(fn)
    def decorated(*args, **kwargs):
        check_basic()
        return fn(*args, **kwargs)
    return decorated
