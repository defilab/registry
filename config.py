import os

basedir = os.path.dirname(os.path.abspath(__file__))

################################
# load variables from .env file
################################


def load_env_from_file(filename):
    filepath = os.path.join(basedir, filename)
    if not os.path.exists(filepath):
        return
    from dotenv import load_dotenv
    load_dotenv(filepath, override=True)


def preload_env_files():
    load_env_from_file('.env')
    load_env_from_file('.env.secret')

    env = os.environ.get('FLASK_ENV', 'production')
    app = os.environ.get('APP', '')

    load_env_from_file(f'.env.{env}')
    if app:
        load_env_from_file(f'.env.{app}')
        load_env_from_file(f'.env.{app}.{env}')
        load_env_from_file(f'.env.{app}.secret')
    load_env_from_file(f'.env.local')


preload_env_files()

################################
# Config for environments
################################


class Config:
    CA_ROOT_CRT = os.environ.get('CA_ROOT_CRT') or 'hard to guess string'
    CA_ROOT_KEY = os.environ.get('CA_ROOT_KEY') or 'hard to guess string'
    JWT_PRIVATE_KEY = os.environ.get('JWT_PRIVATE_KEY') or 'hard to guess string'
    JWT_PUBLIC_KEY = os.environ.get('JWT_PUBLIC_KEY') or 'hard to guess string'
    JWT_ISSUER = 'https://defilab.com' # in seconds
    JWT_ACCESS_EXP = 604800 # in seconds
    JWT_REFRESH_EXP = 2592000 # in seconds


    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.office365.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'noreply@defilab.com')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_POOL_SIZE = 30
    SQLALCHEMY_MAX_OVERFLOW = 20
    SQLALCHEMY_POOL_TIMEOUT = 30


    ELASTIC_ENDPOINT = os.environ.get('ELASTIC_ENDPOINT')

    LEDGER_CFG = os.environ.get('LEDGER_CFG')
    LEDGER_CHAN = os.environ.get('LEDGER_CHAN')
    LEDGER_ENDPOINT = os.environ.get('LEDGER_ENDPOINT')
    LEDGER_NAME = os.environ.get('LEDGER_NAME')
    LEDGER_PEER = os.environ.get('LEDGER_PEER')

    @staticmethod
    def init_app(app):
        pass

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL')
    SQLALCHEMY_ECHO = True


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL')


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
