from functools import lru_cache
import hashlib
from flask import request
from ..crypto import verify_signature
from ..models import Cert, CertState
from ..exception import InvalidSignature, MissingSignParameters, NotFoundCert, TimestampExpired
from ..util import timestamp

def cache(fn):
    cached = {}
    def wrapper(namespace):
        if namespace not in cached or cached[namespace]['timestamp'] <= timestamp():
            cert = fn(namespace)
            cached[namespace] = { 'cert': cert.content, 'timestamp': timestamp() + 3000  }
            return cert.content
        else:
            return cached[namespace]['cert']
    return wrapper

def check_sign(signature):
    required = {'client_id', 'timestamp'}
    if  required - set(request.args.keys()):
        raise MissingSignParameters('missing one of required param: %s' % required)

    cert = get_cert(request.args['client_id'])
    if not cert:
        raise NotFoundCert()
    msg = calculate_msg_to_sign(request.path, request.args)
    verify_signature(cert, signature, msg)
    return True

@cache
def get_cert(namespace):
    cert = Cert.query.filter_by(namespace=namespace, state=CertState.active).one_or_none()
    if not cert:
        raise NotFoundCert()
    return cert

def calculate_msg_to_sign(path, queries):
    sorted_pairs = [
        key + '=' + str(queries[key])
        for key in sorted(queries.keys())
    ]
    canonical_querystring = '&'.join(sorted_pairs)
    return path + '?' + canonical_querystring
