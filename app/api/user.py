from flask import jsonify
from app import db
from ..auth import authorize
from ..extention import RegistryBlueprint
from ..exception import AccountLocked, InvalidEmailAddress, NowAllowUpdateReviewingRequest, NotAuthorized, PasswordNotMatch
from ..models import Request, RequestState, User, UserState
from ..helper import paginate
from ..util import validate_email
from ..validator import validate, attr, roles, Group

bp = RegistryBlueprint('user', __name__)


@bp.route('/', methods=['GET'])
@authorize('token')
@validate(roles(roles.admin))
def all(ctx):
    return jsonify(paginate(User.find(**ctx.request.args)))


@bp.route('/', methods=['POST'])
@authorize('token')
@validate(roles(roles.admin))
@validate(attr.require('username', 'password').forbid('password_hash', 'state'))
def create(ctx):
    if not validate_email(ctx.request.json['username']):
        raise InvalidEmailAddress()

    passwd = ctx.request.json.pop('password', None)
    obj = User(**ctx.request.json)
    if passwd:
        obj.set_password(passwd)
    db.session.add(obj)
    db.session.commit()
    db.session.refresh(obj)
    return jsonify(obj.to_dict())


@bp.route('/<int:user_id>', methods=['GET'])
@authorize('token')
@validate(roles(roles.admin))
def get(ctx, user_id):
    obj = User.query.get_or_404(user_id)
    return jsonify(obj.to_dict())


@bp.route('/<int:user_id>', methods=['PATCH'])
@authorize('token')
@validate(roles(roles.admin, roles.owner('user')))
@validate(attr.forbid('namespace', 'password_hash'))
@validate(
    attr.allow('first_name', 'last_name', require=[Group('old_password', 'password')]).roles(roles.owner('user'))
)
def update(ctx, user_id):
    user = User.query.get_or_404(user_id)
    if user.state == UserState.locked:
        raise AccountLocked()
    if 'password' in ctx.request.json and 'old_password' in ctx.request.json:
        if not user.check_password_and_lock_if_need(ctx.request.json['old_password']):
            raise PasswordNotMatch()
        user.set_password(ctx.request.json['password'])
        user.update(commit=True)
    else:    
        user.update(**ctx.request.json, commit=True)
    return jsonify(user.to_dict())


@bp.route('/<int:user_id>', methods=['DELETE'])
@authorize('token')
@validate(roles(roles.admin))
def delete(user_id):
    obj = User.query.get_or_404(user_id).delete()
    return jsonify(obj.to_dict())

####################################
# Request Management
####################################

@bp.route('/<int:user_id>/requests', methods=['GET'])
@authorize('token')
@validate(roles(roles.owner('user')))
def list_requests(ctx, user_id):
    query = Request.query.find(created_by=user_id, **ctx.request.args)\
                         .filter(Request.state != RequestState.deleted)
    return jsonify(paginate(query))


@bp.route('/<int:user_id>/requests/<int:request_id>', methods=['PATCH'])
@authorize('token')
@validate(roles(roles.owner('user')))
@validate(attr.allow('content')) # TODO state in pending, reviewing
def update_request(ctx, user_id, request_id):
    obj = Request.query.get_or_404(request_id).delete()
    if obj.created_by != user_id:
        raise NotAuthorized()

    if obj.state == RequestState.reviewing:
        raise NowAllowUpdateReviewingRequest()

    obj.update(**ctx.request.json, commit=True)
    return jsonify(obj.to_dict())


@bp.route('/<int:user_id>/requests/<int:request_id>', methods=['DELETE'])
@authorize('token')
@validate(roles(roles.owner('user')))
def delete_request(ctx, user_id, request_id):
    obj = Request.query.get_or_404(request_id).delete()
    if obj.created_by != user_id:
        raise NotAuthorized()
    return jsonify(obj.to_dict())
