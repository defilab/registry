from functools import wraps
from .oauth import oauth, authorization, setup_oauth
from .basic import check_basic
from .sign import check_sign
from ..exception import InvalidAuthorizationMethod, InvalidAuthorizationHeader, MissingAuthorizationHeader, UnsupportedHttpMethod


def authorize(*methods):
    methods = methods or ['sign']

    def decorator(fn):
        @wraps(fn)
        def wrapper(ctx, *args, **kwargs):
            if not methods == ['none']:
                if 'Authorization' in ctx.request.headers:
                    atype, ainfo = ctx.request.headers['Authorization'].split(None, 1)
                    atype = atype.lower()
                    if atype == 'basic':
                        check_basic()
                    elif atype == 'bearer':
                        token = oauth.acquire_token()
                        ctx.namespace = token.get('namespace')
                        ctx.user_id = token['sub']
                        ctx.client = 'user'
                    else:
                        raise InvalidAuthorizationMethod()
                elif 'X-SIGN' in ctx.request.headers:
                    check_sign(ctx.request.headers['X-SIGN'])
                    ctx.namespace = ctx.request.args['client_id']
                    ctx.client = 'sdk'
                else:
                    raise MissingAuthorizationHeader()
            return fn(ctx, *args, **kwargs)
        return wrapper
    return decorator


def generate_reset_password_token():
    pass
