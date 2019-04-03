from datetime import datetime
from functools import partial
from io import BytesIO
from flask import current_app, request, jsonify, send_file
from sqlalchemy import or_
from app import db, ledger
from ..auth import authorize
from ..crypto import load_csr, load_crt, load_key, sign_csr
from ..exception import AlreadyHaveRequestInProcess, AlreadyExists, UserAlreadyHaveOrganization
from ..extention import RegistryBlueprint
from ..helper import paginate
from ..models import Cert, CertState, Field, Organization, Request, RequestState, Spec, User
from ..util import batch_async_call
from ..validator import validate, attr, value, roles, Not, Eq

bp = RegistryBlueprint('organization', __name__)


def check_new_request_or_400(kind, owner=None, namespace=None, resource_id=None):
    query = Request.query.filter(Request.request_type==kind)\
                         .filter(Request.state.in_([
                            RequestState.pending,
                            RequestState.reviewing
                         ]))
    if owner:
        query = query.filter(Request.created_by==owner)

    if namespace:
        query = query.filter(Request.namespace==namespace)

    if resource_id:
        query = query.filter(Request.resource_id==resource_id)

    req = query.first()
    if req:
        raise AlreadyHaveRequestInProcess()
    return req


def abort_if_exists(model, custom_filter=None, **kwargs):
    query = model.query.filter_by(**kwargs)
    if custom_filter is not None:
        query = query.filter(custom_filter)
    if query.first():
        raise AlreadyExists('resource already exists')

###################################
# Organization Management
###################################


@bp.route('/', methods=['GET'])
@authorize('token')
@validate(roles(roles.admin))
def all(ctx):
    query = Organization.find(**request.args)
    return jsonify(paginate(query))


@bp.route('/', methods=['POST'])
@authorize('token')
@validate(
    roles(roles.user),
    attr.allow('introduction', 'properties', 'public', 'state', require=['name', 'namespace', 'role'])
)
def create(ctx):
    user = User.get_or_404(id=ctx.user_id)
    if not roles.admin(ctx) and user.namespace:
        raise UserAlreadyHaveOrganization()

    if roles.admin(ctx):
        obj = Organization.create(**request.json, commit=True)
        return jsonify(obj.to_dict())

    check_new_request_or_400('create_organization', owner=ctx.user_id)
    abort_if_exists(
        Organization,
        custom_filter=or_(
            Organization.name == request.json['name'],
            Organization.namespace == request.json['namespace']
        ))

    payload = {
        'request_type': 'create_organization',
        'resource': 'organization',
        'created_by': ctx.user_id,
        'content': request.json,
        'state': RequestState.reviewing,
    }
    Request.create(**payload, commit=True)
    return jsonify({'message': 'requested'})


@bp.route('/<string:namespace>', methods=['GET'])
@authorize('token')
@validate(roles(roles.admin, roles.owner('namespace')))
def get(ctx, namespace):
    obj = Organization.get_or_404(namespace=namespace).to_dict()
    obj['balance'] = ledger.get_balance(namespace)
    income = partial(ledger.get_income, namespace)
    expense = partial(ledger.get_expense, namespace)
    ret = batch_async_call({
        'income_today': partial(income, today=True),
        'income_month': partial(income, month=True),
        'income_total': income,
        'expense_today': partial(expense, today=True),
        'expense_month': partial(expense, month=True),
        'expense_total': expense,
    })
    obj['income'] = {
        'today': ret['income_today'],
        'month': ret['income_month'],
        'total': ret['income_total'],
    }
    obj['expense'] = {
        'today': ret['expense_today'],
        'month': ret['expense_month'],
        'total': ret['expense_total'],
    }     
    return jsonify(obj)


@bp.route('/<string:namespace>', methods=['PATCH'])
@authorize('token')
@validate(roles(roles.admin, roles.owner('namespace')))
def update(ctx, namespace):
    org = Organization.get_or_404(namespace=namespace)

    if roles.admin(ctx):
        org.update(**request.json, commit=True)
        return jsonify(org.to_dict())

    check_new_request_or_400('update_organization', resource_id=org.id)

    payload = {
        'namespace': org.namespace,
        'request_type': 'update_organization',
        'resource': 'organization',
        'resource_id': org.id,
        'created_by': ctx.user_id,
        'content': request.json,
        'state': RequestState.reviewing,
    }

    Request.create(**payload, commit=True)
    return jsonify({'message': 'requested'})


@bp.route('/<string:namespace>', methods=['DELETE'])
@authorize('token')
@validate(roles(roles.admin))
def delete(ctx, namespace):
    obj = Organization.get_or_404(namespace=namespace).delete()
    return jsonify(obj.to_dict())

###################################
# Certificate Management
###################################


@bp.route('/<string:namespace>/certs', methods=['GET'])
@authorize('token')
@validate(roles(roles.admin, roles.owner('namespace')))
def list_certs(ctx, namespace):
    query = Cert.find(namespace=namespace, **request.args)
    if not roles.admin(request):
        query = query.filter(Cert.state==CertState.active)
    return jsonify(paginate(query))


@bp.route('/<string:namespace>/certs/<string:fingerprint>', methods=['GET'])
@authorize('sign', 'token')
@validate(roles(roles.owner))
def get_cert(ctx, namespace, fingerprint):
    options = {
        'namespace': namespace,
        'fingerprint': fingerprint,
    }
    if not roles.admin(request):
        options['state'] = CertState.active
    cert = Cert.get_or_404(**options)
    return jsonify(cert.to_dict())


@bp.route('/<string:namespace>/certs/active/download', methods=['GET'])
@authorize('token')
@validate(roles(roles.owner))
def download_cert_file(ctx, namespace):
    cert = Cert.get_or_404(namespace=namespace, state=CertState.active)
    memory_file = BytesIO(cert.content.encode())
    return send_file(memory_file, attachment_filename='cert.pem', as_attachment=True)


@bp.route('/<string:namespace>/certs', methods=['POST'])
@authorize('token')
@validate(roles(roles.owner('namespace'), roles.admin))
def upload_cert(ctx, namespace):
    abort_if_exists(Cert, namespace=namespace, state=CertState.active)
    data = request.get_data()
    if not data and 'file' in request.files:
        data = request.files['file'].read()

    csr = load_csr(data.decode())
    ca_crt = load_crt(current_app.config['CA_ROOT_CRT'])
    ca_key = load_key(current_app.config['CA_ROOT_KEY'])
    fingerprint, crt = sign_csr(csr, ca_crt, ca_key)
    obj = Cert.create(namespace=namespace, fingerprint=fingerprint, content=crt, commit=True)
    return jsonify({'message': 'success', 'fingerprint': fingerprint})


@bp.route('/<string:namespace>/certs/<string:fingerprint>', methods=['DELETE'])
@authorize('token')
@validate(roles(roles.owner('namespace')))
def delete_cert(ctx, namespace, fingerprint):
    obj = Cert.get_or_404(namespace=namespace, fingerprint=fingerprint)\
              .deleted()
    return jsonify(obj.to_dict())


@bp.route('/<string:namespace>/ledger/files/download', methods=['GET'])
@authorize('token')
@validate(roles(roles.owner('namespace')))
def download_ledger_files(ctx, namespace):
    obj = Organization.get_or_404(namespace=namespace)
    memory_file = BytesIO(obj.ledger_files)
    return send_file(memory_file, attachment_filename='ledger_files.zip', as_attachment=True)

###################################
# Field Management
###################################


@bp.route('/<string:namespace>/fields', methods=['GET'])
@authorize('token')
@validate(
    roles(roles.owner('namespace'), roles.user),
    value('path').ensure(namespace=Eq('platform')).roles(Not(roles.owner('namespace')))
)
def list_fields(ctx, namespace):
    query = Field.find(namespace=namespace, **request.args)
    return jsonify(paginate(query))


@bp.route('/<string:namespace>/fields', methods=['POST'])
@authorize('token')
@validate({
    roles(roles.owner('namespace')),
    attr.allow(require=['name', 'canonical_name']).forbid('namespace')
})
def create_field(ctx, namespace):
    abort_if_exists(
        Field,
        namespace=namespace,
        canonical_name=request.json['canonical_name']
    )
    request.json['namespace'] = namespace
    payload = {
        'namespace': namespace,
        'request_type': 'create_field',
        'resource': 'field',
        'created_by': ctx.user_id,
        'content': request.json,
        'state': RequestState.reviewing,
    }
    Request.create(**payload, commit=True)
    return jsonify({'message': 'requested'})


@bp.route('/<string:namespace>/fields/<string:canonical_name>', methods=['GET'])
@authorize('token')
@validate(roles(roles.owner('namespace')))
def get_field(ctx, namespace, canonical_name):
    obj = Field.get_or_404(namespace=namespace, canonical_name=canonical_name)
    return jsonify(obj.to_dict())


@bp.route('/<string:namespace>/fields/<string:canonical_name>', methods=['PATCH'])
@authorize('token')
@validate(
    roles(roles.owner('namespace')),
    attr.forbid('namespace')
)
def update_field(ctx, namespace, canonical_name):
    field = Field.get_or_404(namespace=namespace, canonical_name=canonical_name)
    check_new_request_or_400('update_field', resource_id=field.id)
    payload = {
        'namespace': field.namespace,
        'request_type': 'update_field',
        'resource': 'field',
        'resource_id': field.id,
        'created_by': ctx.user_id,
        'content': request.json,
        'state': RequestState.reviewing,
    }

    Request.create(**payload, commit=True)
    return jsonify({'message': 'requested'})


@bp.route('/<string:namespace>/fields/<string:canonical_name>', methods=['DELETE'])
@authorize('token')
@validate(roles(roles.owner('namespace')))
def delete_field(ctx, namespace, canonical_name):
    obj = Field.get_or_404(namespace=namespace, canonical_name=canonical_name)\
               .delete()
    return jsonify(obj.to_dict())

###################################
# Spec Management
###################################


@bp.route('/<string:namespace>/specs', methods=['GET'])
@authorize('token')
@validate(
    roles(roles.owner('namespace'), roles.user),
    value('path').ensure(namespace=Eq('platform')).roles(Not(roles.owner('namespace')))
)
def list_specs(ctx, namespace):
    query = Spec.find(namespace=namespace, **request.args)
    return jsonify(paginate(query))


@bp.route('/<string:namespace>/specs', methods=['POST'])
@authorize('token')
@validate(
    roles(roles.owner('namespace')),
    attr.require('name', 'canonical_name').forbid('namespace')
)
def create_spec(ctx, namespace):
    abort_if_exists(
        Spec,
        namespace=namespace,
        canonical_name=request.json['canonical_name']
    )
    request.json['namespace'] = namespace
    payload = {
        'namespace': namespace,
        'request_type': 'create_spec',
        'resource': 'spec',
        'created_by': ctx.user_id,
        'content': request.json,
        'state': RequestState.reviewing,
    }
    Request.create(**payload, commit=True)
    return jsonify({'message': 'requested'})    


# TODO
# 获取data spec完整的符合OPENAPI + JSON SCHEMA标准的完整的定义.
@bp.route('/<string:namespace>/specs/<string:canonical_name>', methods=['GET'])
@authorize('token')
@validate(roles(roles.owner('namespace')))
def get_spec(ctx, namespace, canonical_name):
    obj = Spec.get_or_404(namespace=namespace, canonical_name=canonical_name)
    return jsonify(obj.to_dict())


@bp.route('/<string:namespace>/specs/<string:canonical_name>', methods=['PATCH'])
@authorize('token')
@validate(attr.forbid('namespace'))
@validate(roles(roles.owner('namespace')))
def update_spec(ctx, namespace, canonical_name):
    spec = Spec.get_or_404(namespace=namespace, canonical_name=canonical_name)
    if 'state' in request.json and len(request.json.keys()) == 1: # 只是更新状态
        spec.update(state=request.json['state'], commit=True)
        return jsonify({'message': 'success'})

    check_new_request_or_400('update_spec', resource_id=spec.id)

    payload = {
        'namespace': namespace,
        'request_type': 'update_spec',
        'resource': 'spec',
        'resource_id': spec.id,
        'created_by': ctx.user_id,
        'content': request.json,
        'state': RequestState.reviewing,
    }

    Request.create(**payload, commit=True)
    return jsonify({'message': 'requested'})


@bp.route('/<string:namespace>/specs/<string:canonical_name>', methods=['DELETE'])
@authorize('token')
@validate(roles(roles.owner('namespace')))
def delete_spec(ctx, namespace, canonical_name):
    obj = Spec.get_or_404(namespace=namespace, canonical_name=canonical_name)\
              .delete()
    return jsonify(obj.to_dict())


@bp.route('/<string:namespace>/specs/<string:canonical_name>/beat', methods=['POST'])
@authorize('sign', 'token')
@validate(roles(roles.admin, roles.owner('namespace'), roles.sdk))
def spec_heart_beat(ctx, namespace, canonical_name):
    obj = Spec.get_or_404(namespace=namespace, canonical_name=canonical_name)
    obj.last_beat_at = datetime.utcnow()
    db.session.add(obj)
    db.session.commit()
    return jsonify({'message': 'success'})

###################################
# Transacrtion Management
###################################


@bp.route('/<string:namespace>/transactions/request', methods=['GET'])
@authorize('token')
@validate(roles(roles.admin, roles.owner('namespace')))
def list_request_transactions(ctx, namespace):
    items = ledger.get_request_offers(namespace)
    return jsonify(items=items)


@bp.route('/<string:namespace>/transactions/response', methods=['GET'])
@authorize('token')
@validate(roles(roles.admin, roles.owner('namespace')))
def list_response_transactions(ctx, namespace):
    items = ledger.get_response_offers(namespace)
    return jsonify(items=items)


@bp.route('/<string:namespace>/transactions/balance', methods=['GET'])
@authorize('token')
@validate(roles(roles.admin, roles.owner('namespace')))
def list_balance_transactions(namespace):
    items = ledger.get_balance_transactions(namespace)
    return jsonify(items=items)


###################################
# Requests Management
###################################
@bp.route('/<string:namespace>/requests', methods=['GET'])
@authorize('token')
@validate(roles(roles.admin, roles.owner('namespace')))
def list_requests(namespace):
    query = Request.find(namespace=namespace, **request.args)
    return jsonify(paginate(query))
