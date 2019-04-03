import jwt
from authlib.flask.oauth2 import AuthorizationServer, ResourceProtector
from authlib.specs.rfc6749 import grants, InvalidGrantError, InvalidRequestError
from authlib.specs.rfc6750 import BearerTokenValidator
from flask import current_app

from ..exception import AccountLocked, PasswordNotMatch
from ..models import Organization, User, UserState
from ..util import timestamp

authorization = AuthorizationServer()
oauth = ResourceProtector()

def setup_oauth(app):
    authorization.init_app(app)

    authorization.register_grant(PasswordGrant)
    authorization.register_grant(RefreshTokenGrant)
    oauth.register_token_validator(JwtTokenValidator())

def create_token(subject, payload, exp_in=60, scope=None, token_use='access'):
    payload['token_use'] = token_use
    payload['sub'] = subject
    payload['iss'] = current_app.config['JWT_ISSUER']
    payload['iat'] = timestamp()
    payload['exp'] = payload['iat'] + exp_in

    payload['aud'] = 'registry-portal'
    if scope:
        payload['scope'] = scope

    private_key = current_app.config['JWT_PRIVATE_KEY']
    return jwt.encode(payload, private_key, algorithm='RS256').decode('utf-8')

def decode_token(token):
    public_key = current_app.config['JWT_PUBLIC_KEY']
    options = {'verify_aud': False, 'require_sub': True}
    return jwt.decode(token, public_key, algorithms=['RS256'], options=options)

class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    def validate_token_request(self):
        params = self.request.data
        if 'username' not in params:
            raise InvalidRequestError('Missing "username" in request.')
        if 'password' not in params:
            raise InvalidRequestError('Missing "password" in request.')

        user = self.authenticate_user(
            params['username'],
            params['password']
        )
        if not user:
            raise InvalidGrantError(
                'Invalid "username" or "password" in request.',
            )
        self.request.user = user

    def authenticate_user(self, username, password):
        user = User.find(username=username).one_or_none()
        if user:
            if user.state == UserState.locked:
                raise AccountLocked()
            if not user.check_password_and_lock_if_need(password):
                raise PasswordNotMatch()
            return user.to_dict()
        return None

    def create_token_response(self):
        payload = dict(self.request.user)
        user_id = payload.pop('id')
        if payload['namespace']:
            org = Organization.get_or_404(namespace=payload['namespace']).to_dict()
            payload['organization_role'] = org['role']
            payload['organization_state'] = org['state']

        access_token = create_token(user_id, payload, token_use='access', exp_in=current_app.config['JWT_ACCESS_EXP'])
        refresh_token = create_token(user_id, payload, token_use='refresh', exp_in=current_app.config['JWT_REFRESH_EXP'])
        return 200, dict(access_token=access_token, refresh_toke=refresh_token, token_type='bearer', expires_in=current_app.config['JWT_ACCESS_EXP']), self.TOKEN_RESPONSE_HEADER

class RefreshTokenGrant(grants.RefreshTokenGrant):
    def authenticate_refresh_token(self, refresh_token):
        try:
            return decode_token(refresh_token)
        except Exception as e:
            raise InvalidRequestError('invalid refresh token')

    def authenticate_user(self, credential):
        user = User.query.filter_by(id=credential['id']).one_or_none()
        if not user:
            raise InvalidGrantError(
                'subject does not exists',
            )
        return user.to_dict()

    def validate_token_request(self):
        refresh_token = self.request.data.get('refresh_token')
        if refresh_token is None:
            raise InvalidRequestError('Missing "refresh_token" in request.')
        token = self.authenticate_refresh_token(refresh_token)
        if (token['iss'] != current_app.config['JWT_ISSUER']
                or token['token_use'] != 'refresh'):
            raise InvalidGrantError('invalid refresh_token')
        if token['exp'] < timestamp():
            raise InvalidGrantError('refresh_token is expired')
        self.request.credential = token

    def create_token_response(self):
        user = self.authenticate_user(self.request.credential)
        access_token = create_token(user['id'], user, token_use='access', exp_in=current_app.config['JWT_ACCESS_EXP'])
        refresh_token = create_token(user['id'], user, token_use='refresh', exp_in=current_app.config['JWT_REFRESH_EXP'])
        return 200, dict(access_token=access_token, refresh_toke=refresh_token, token_type='bearer', expires_in=current_app.config['JWT_REFRESH_EXP']), self.TOKEN_RESPONSE_HEADER     

class JwtTokenValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        return decode_token(token_string)

    def request_invalid(self, request):
        return False

    def token_revoked(self, token):
        return False

    def token_expired(self, token):
        return token['exp'] < timestamp()
