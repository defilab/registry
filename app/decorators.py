from functools import wraps
from flask import request
from app import db
from app.models import Audit


def audit(operation, resource, composed_resource_id, reference=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            resp = fn(*args, **kwargs)
            evt(operation, resource, composed_resource_id, reference=reference)
            return resp
        return wrapper
    return decorator


def evt(operation, resource, composed_resource_id, event=None, reference=None):
    try:
        kwargs = {
            'resource': resource,
            'operation': operation,
            'resource_id': find_resource_id(composed_resource_id),
        }
        if not reference:
            if hasattr(request, 'user_id'):
                reference = 'user:' + request.user_id
            elif hasattr(request, 'client') and hasattr(request, 'namespace'):
                reference = 'space:{}:client:'.format(request.namespace, request.client)
            elif hasattr(request, 'namespace'):
                reference = 'space:{}:'.format(request.namespace)
            else:
                reference = 'unknown'
        kwargs['reference'] = reference

        if not event and request.method in ['PATCH', 'POST', 'PUT']:
            event = request.json
        if 'password' in event:
            event['password'] = '***'
        if 'old_password' in event:
            event['old_password'] = '***'            
        kwargs['event'] = event

        Audit.create(db.session, **kwargs)
    except Exception as e:
        print(e)


def find_resource_id(rid):
    if type(rid) == str:
        src, name =  rid.split(':', 1)
        if src == 'path':
            return request.view_args[name]
        elif src == 'query':
            return request.args[name]
        elif src == 'body':
            return request.json[name]
    return rid
