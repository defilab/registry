from flask import Blueprint, request, jsonify
from ..auth import authorize
from ..extention import RegistryBlueprint
from ..helper import paginate
from ..models import Field
from ..validator import validate, attr, roles

bp = RegistryBlueprint('field', __name__)


@bp.route('/', methods=['GET'])
@authorize('token')
@validate(roles(roles.admin))
def all(ctx):
    return jsonify(paginate(Field.find(**ctx.request.args)))


@bp.route('/', methods=['POST'])
@authorize('token')
@validate(
    roles(roles.admin),
    attr.allow(
        'definition', 'introduction', 'localization', 'properties',
        require=['canonical_name', 'name', 'namespace']
    ).forbid('id', 'version')
)
def create(ctx):
    obj = Field.create(**request.json, commit=True)
    return jsonify(obj.to_dict())


@bp.route('/<int:field_id>', methods=['GET'])
@authorize('token')
@validate(roles(roles.admin))
def get(ctx, field_id):
    obj = Field.query.get_or_404(field_id)
    return jsonify(obj.to_dict())


@bp.route('/<int:field_id>', methods=['PATCH'])
@authorize('token')
@validate(
    roles(roles.admin),
    attr.allow(
        'definition', 'introduction', 'localization', 'name', 'properties'
    ).forbid('canonical_name', 'id', 'namespace', 'version')
)
def modify(ctx, field_id):
    obj = Field.query.get_or_404(field_id)
    obj.update(**request.json, commit=True)
    return jsonify(obj.to_dict())

