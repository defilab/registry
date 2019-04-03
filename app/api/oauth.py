from ..auth import authorize, authorization
from ..extention import RegistryBlueprint

bp = RegistryBlueprint('auth', __name__)


@bp.route('/tokens', methods=['POST'])
@authorize('basic')
def access_token(ctx):
    return authorization.create_token_response()
