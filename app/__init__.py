from flask_mail import Mail
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy 
from config import config
from .extention import RegistryFlask, PowerfulQuery
from .ledger import Ledger

mail = Mail()
db = SQLAlchemy(query_class=PowerfulQuery)
ledger = Ledger()


def create_app(config_name):
    app = RegistryFlask(__name__)
    app.url_map.strict_slashes = False
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    CORS(app, supports_credentials=True)
    mail.init_app(app)
    db.init_app(app)
    ledger.init_app(app)

    from .auth import setup_oauth
    setup_oauth(app)

    from .api.oauth import bp as oauth_bp
    app.register_blueprint(oauth_bp, url_prefix='/oauth')

    from .api.organization import bp as org_bp
    app.register_blueprint(org_bp, url_prefix='/organizations')

    from .api.user import bp as user_bp
    app.register_blueprint(user_bp, url_prefix='/users')

    from .api.cert import bp as cert_bp
    app.register_blueprint(cert_bp, url_prefix='/certs')

    from .api.field import bp as field_bp
    app.register_blueprint(field_bp, url_prefix='/fields')

    from .api.spec import bp as spec_bp
    app.register_blueprint(spec_bp, url_prefix='/specs')

    from .api.request import bp as req_bp
    app.register_blueprint(req_bp, url_prefix='/requests')

    from .error import setup_errorhandler
    setup_errorhandler(app)

    return app
