from flask import jsonify
from ..auth import authorize
from ..extention import RegistryBlueprint
from ..helper import paginate
from ..models import Cert
from ..validator import validate, roles

bp = RegistryBlueprint('cert', __name__)


@bp.route('/', methods=['GET'])
@authorize('token')
@validate(roles(roles.admin))
def all(ctx):
    return jsonify(paginate(Cert.find(**ctx.request.args)))


@bp.route('/<string:fingerprint>', methods=['GET'])
@authorize('sign', 'token')
@validate(roles(roles.admin, roles.sdk))
def get(ctx, fingerprint):
    obj = Cert.get_or_404(fingerprint=fingerprint)
    return jsonify(obj.to_dict())
