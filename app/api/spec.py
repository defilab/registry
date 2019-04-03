from datetime import datetime, timedelta
from flask import request, jsonify
from ..auth import authorize
from ..extention import RegistryBlueprint
from ..helper import paginate, flatten, extract_space_and_name
from ..models import Cert, CertState, Organization, Spec, SpecState
from ..validator import validate, attr, roles

bp = RegistryBlueprint('spec', __name__)


@bp.route('/', methods=['GET'])
@authorize('token')
@validate(roles(roles.admin))
def all(ctx):
    query = Spec.find(**request.args)
    if not roles.admin(ctx):
        query = query.filter(Spec.public==True)
    return jsonify(paginate(query))


@bp.route('/', methods=['POST'])
@authorize('token')
@validate(
    roles(roles.admin),
    attr.require('name')
)
def create(ctx):
    obj = Spec.create(**request.json, commit=True)
    return jsonify(obj.to_dict())


@bp.route('/<int:spec_id>', methods=['PATCH'])
@authorize('token')
@validate(
    roles(roles.admin)
)
def update(ctx, spec_id):
    obj = Spec.query.get_or_404(spec_id)
    obj.update(**request.json, commit=True)
    return jsonify(obj.to_dict())


@bp.route('/<int:spec_id>', methods=['GET'])
@authorize('token')
@validate(roles(roles.admin))
def get(ctx, spec_id):
    return jsonify(Spec.query.get_or_404(spec_id).to_dict())

####################################
# Cert Management
####################################


def get_region(ctx):
    region = ctx.request.args.get('region')
    if not region:
        region = Organization.get_or_404(namespace=ctx.namespace).region
    return region


def select_certs_of_alive_spec(query, canonical_name, region):
    beat_timeout_at = datetime.utcnow() - timedelta(minutes=5)
    query = query.filter(Cert.state==CertState.active)\
                      .join(Spec, Cert.namespace==Spec.namespace)\
                      .filter(Spec.last_beat_at>=beat_timeout_at) \
                      .filter(Spec.region==region)\
                      .filter(Spec.state==SpecState.online)

    space, name = extract_space_and_name(canonical_name)
    if space and space != 'platform':
        query = query.filter(Cert.namespace==space).filter(Spec.canonical_name==name)
    else:
        query = query.filter(Spec.reference==name)
    return query


@bp.route('/<string:canonical_name>/certs', methods=['GET'])
@authorize('sign', 'token')
@validate(roles(roles.admin, roles.sdk))
def list_certs(ctx, canonical_name):

    query = select_certs_of_alive_spec(Cert.query, canonical_name, get_region(ctx))
    return jsonify(paginate(query))


@bp.route('/<string:canonical_name>/fingerprints', methods=['GET'])
@authorize('sign', 'token')
@validate(roles(roles.admin, roles.sdk))
def list_fingerprints(ctx, canonical_name):
    query = select_certs_of_alive_spec(
        Cert.query.with_entities(Cert.fingerprint),
        canonical_name,
        get_region(ctx)
    )
    return jsonify(paginate(query, callback=flatten))
