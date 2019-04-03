from flask import jsonify
from authlib.specs.rfc6749.errors import MissingAuthorizationError
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError
from .exception import RegistryException


def setup_errorhandler(app):
    @app.errorhandler(MissingAuthorizationError)
    @app.errorhandler(ExpiredSignatureError)
    @app.errorhandler(InvalidSignatureError)
    @app.errorhandler(RegistryException)
    def handle_authorize_error(error):
        status_code = 401
        response = {}
        if isinstance(error, RegistryException):
            response = error.to_dict()
            status_code = status_code
        else:
            response['error'] = error.__class__.__name__

        return jsonify(response), status_code

    @app.errorhandler(404)
    def handle_not_found_error(error):
        return jsonify({ 'error': 'not found' }), 404

    if app.config['ENV'] == 'production':
        @app.errorhandler(Exception)
        def handle_unexpected_error(error):
            if app.config['ENV'] != 'production':
                raise error

            status_code = 500
            success = False
            response = {
                'error': 'server internal error',
                'message': 'an unexpected error has occurred'
            }
            return jsonify(response), status_code
