from collections import defaultdict
from datetime import datetime
from flask import request, jsonify
from app import db
from ..auth import authorize
from ..exception import NotFound, RequestHasBeenAccepted
from ..extention import RegistryBlueprint
from ..helper import paginate
from ..models import Field, Spec, Organization, Request, RequestState, User
from ..util import isotime
from ..validator import validate, attr, roles

bp = RegistryBlueprint('request', __name__)


@bp.route('/', methods=['GET'])
@authorize('token')
@validate(roles(roles.admin))
def all(ctx):
    return jsonify(paginate(Request.find(**request.args)))


@bp.route('/<int:request_id>', methods=['GET'])
@authorize('token')
@validate(roles(roles.admin))
def get(ctx, request_id):
    return jsonify(Request.query.get_or_404(request_id).to_dict())


@bp.route('/<int:request_id>', methods=['PATCH'])
@authorize('token')
@validate(
    roles(roles.admin),
    attr.allow('state', 'comment')
)
def update(ctx, request_id):
    req = Request.query.get_or_404(request_id)
    if req.state == RequestState.deleted:
        raise NotFound()

    if req.state == RequestState.accepted:
        raise RequestHasBeenAccepted('cannot update accepted requests')

    if 'state' in request.json:
        if req.state in[RequestState.pending, RequestState.reviewing] and request.json['state'] == 'accepted':
            req.state = RequestState.accepted
            if req.request_type == ('create_' + req.resource):
                create_resource(req)            
            elif req.request_type == ('update_' + req.resource) and req.resource_id is not None:
                update_resource(req)
            else:
                raise BadRequest('unknown request_type or incomplete information')
        else:
            req.state = RequestState[request.json['state']]

    if 'comment' in request.json:
        req.comments = req.comments or defaultdict(list)
        req.comments['replies'].append({
            'message': request.json['comment'],
            'timestamp':isotime(datetime.utcnow()),
        })
    db.session.add(req)
    db.session.commit()
    return jsonify({'message': 'success'})


@bp.route('/<int:request_id>', methods=['DELETE'])
@authorize('token')
@validate(roles(roles.admin))
def delete(ctx, request_id):
    obj = Request.query.get_or_404(request_id).delete()
    return jsonify(obj.to_dict())


def create_resource(req):
    if req.resource == 'field':
        obj = Field.create(**req.content)
    elif req.resource == 'organization':
        obj =  Organization.create(**req.content)
        user = User.get_or_404(id=req.created_by)
        user.namespace = obj.namespace
        db.session.add(user)
    elif req.resource == 'spec':
        obj = Spec.create(**req.content)
    db.session.add(obj)


def update_resource(req):
    if req.resource == 'field':
        obj = Field.get_or_404(id=req.resource_id).update(**req.content)
    elif req.resource == 'organization':
        obj = Organization.get_or_404(id=req.resource_id).update(**req.content)
    elif req.resource == 'spec':
        obj = Spec.get_or_404(id=req.resource_id).update(**req.content)
    db.session.add(obj)
