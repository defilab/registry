from collections import defaultdict
from datetime import datetime
import enum
from functools import lru_cache
from flask import current_app, url_for, abort
import pytz
from sqlalchemy import UniqueConstraint
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from werkzeug.security import generate_password_hash, check_password_hash
from app import db


class Base(db.Model):
    __abstract__ = True

    @classmethod
    def find(cls, **kwargs):
        conditions = {
            key : val
            for key, val in kwargs.items() 
            if key in cls._get_filterable_columns()
        }
        return cls.query.filter_by(**conditions)

    @classmethod
    def get_or_404(cls, **kwargs):
        obj = cls.query.filter_by(**kwargs).one_or_none()
        if obj is None:
            abort(404)
        return obj

    @classmethod
    def create(cls, commit=False, **kwargs):
        obj = cls(**kwargs)
        if commit:
            cls.query.session.add(obj)
            cls.query.session.commit()
            cls.query.session.refresh(obj)
        return obj

    def update(self, commit=False, **kwargs):
        from .exception import ShouldNotUpdateReadOnlyColumn

        for key, value in kwargs.items():
            setattr(self, key, value)

        if commit:
            self.query.session.add(self)
            self.query.session.commit()
            self.query.session.refresh(self)
        return self

    def delete(self):
        self.query.session.delete(self)
        self.query.session.commit()
        return self

    def to_dict(self):
        hidden_columns = self._get_hidden_columns()
        model_dict = dict(self.__dict__)
        for column in list(model_dict.keys()):
            if column in hidden_columns:
                del model_dict[column]
            elif isinstance(model_dict[column], enum.Enum):
                model_dict[column] = model_dict[column].name
            elif isinstance(model_dict[column], datetime):
                model_dict[column] = model_dict[column].replace(tzinfo=pytz.utc).isoformat()
        return model_dict

    @classmethod
    def _get_hidden_columns(cls):
        hidden_columns = set(getattr(cls, "_hidden_fields", {'default': []})['default'])
        hidden_columns |= set(['_sa_instance_state'])
        hidden_columns |= set(['updated_at', 'deleted_at', 'created_by', 'updated_by', 'deleted_by'])

        return hidden_columns

    @classmethod
    def _get_filterable_columns(cls):
        hidden_columns = cls._get_hidden_columns()
        filterable_columns = getattr(cls, "_filterable_fields", set())
        if not filterable_columns:
            filterable_columns = set(cls.__table__.columns.keys())
        return filterable_columns - hidden_columns

    @classmethod
    def _get_special_columns(cls, column_type):
        from flask import request
        from .validator import roles
        role_name = 'admin' if roles.admin(request.context) else 'default'
        columns_for_roles = {}
        if column_type == 'hidden' and hasattr(cls, "_hidden_fields"):
            columns_for_roles = cls._hidden_fields
        elif column_type == 'readonly' and hasattr(cls, "_readonly_fields"):
            columns_for_roles = cls._readonly_fields
        elif column_type == 'filterable' and hasattr(cls, "_filterable_fields"):
            columns_for_roles = cls._filterable_fields

        if role_name == 'admin' and role_name in columns_for_roles:
            return columns_for_roles['admin']
        else:
            return columns_for_roles.get('default', [])


class TimestampMixin:
    @declared_attr
    def created_at(cls):
        return db.Column(db.TIMESTAMP, server_default=db.text('CURRENT_TIMESTAMP'))

    @declared_attr
    def updated_at(cls):
        return db.Column(db.TIMESTAMP, server_default=db.text('CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP'))

    @declared_attr
    def deleted_at(cls):
        return db.Column(db.TIMESTAMP)


class OrganizationState(enum.Enum):
    deleted = 0
    active  = 1
    locked  = 2

    def __str__(self):
        return self.name


class OrganizationRole(enum.Enum):
    none = 0
    requester = 1
    provider = 2
    both = 3

    def __str__(self):
        return self.name


class Organization(Base, TimestampMixin):
    __tablename__ = 'organizations'
    _hidden_fields = {'default': ['ledger_passwd', 'ledger_files']}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), index=True, unique=True)
    namespace = db.Column(db.String(64), index=True, unique=True)
    ledger_passwd = db.Column(db.String(32))
    ledger_files = db.Column(db.BLOB)
    introduction = db.Column(MEDIUMTEXT)
    localization = db.Column(db.JSON)
    properties = db.Column(db.JSON)
    public = db.Column(db.Boolean, nullable=False, default=True)
    region = db.Column(db.String(64), index=True, nullable=False)
    role = db.Column(db.Enum(OrganizationRole), nullable=False, default=OrganizationRole.none, index=True)
    state = db.Column(db.Enum(OrganizationState), nullable=False, default=OrganizationState.active, index=True)

    def __repr__(self):
        return '<Organization {}>'.format(self.name)

    @classmethod
    def create(cls, commit=False, **kwargs):
        from . import ledger
        from .util import generate_password
        obj = cls(**kwargs)
        obj.ledger_passwd = generate_password()
        obj.ledger_files  = ledger.create_account(obj.namespace, obj.ledger_passwd)
        if commit:
            cls.query.session.add(obj)
            cls.query.session.commit()
            cls.query.session.refresh(obj)
        return obj

class UserState(enum.Enum):
    pending = 0
    active  = 1
    locked  = 2

    def __str__(self):
        return self.name

class User(Base, TimestampMixin):
    __tablename__ = 'users'
    _hidden_fields = { 'default': ['password_hash'] }

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    namespace = db.Column(db.String(64), db.ForeignKey('organizations.namespace'), index=True)
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    organization = db.relationship("Organization")
    password_hash = db.Column(db.String(128))
    state = db.Column(db.Enum(UserState), nullable=False, default=UserState.pending, index=True)

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def check_password_and_lock_if_need(self, password):
        match = check_password_hash(self.password_hash, password)
        if not match:
            self.failed_login_attempts += 1
            if self.failed_login_attempts >= 5:
                self.state = UserState.locked
            self.update(commit=True)
        return match

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode({'reset_password': self.id, 'exp': time() + expires_in},
            current_app.config['SECRET_KEY'],
            algorithm='HS256').decode('utf-8')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(
                    token, 
                    current_app.config['SECRET_KEY'],
                    algorithms=['HS256']
                )['reset_password']
        except:
            return
        return User.query.get(id)


class CertState(enum.Enum):
    deleted = 0
    active  = 1

    def __str__(self):
        return self.name

class Cert(Base, TimestampMixin):
    __tablename__ = 'certs'

    id = db.Column(db.Integer, primary_key=True)
    namespace = db.Column(db.String(64), db.ForeignKey('organizations.namespace'), nullable=False)
    content = db.Column(db.Text)
    fingerprint = db.Column(db.String(512), index=True, unique=True)
    organization = db.relationship("Organization")
    state = db.Column(db.Enum(CertState), nullable=False, default=CertState.active, index=True)

    def __repr__(self):
        return '<Cert {}>'.format(self.namespace)

    def delete(self):
        self.state = CertState.deleted
        self.query.session.add(self)
        self.query.session.commit()
        return self

class Field(Base, TimestampMixin):
    __tablename__ = 'fields'

    __table_args__ = (
        UniqueConstraint('namespace', 'canonical_name', 'region', 'version'),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), index=True)
    canonical_name = db.Column(db.String(64), index=True, nullable=False)
    namespace = db.Column(db.String(64), db.ForeignKey('organizations.namespace'), nullable=False)
    definition = db.Column(db.JSON)
    introduction = db.Column(MEDIUMTEXT)
    localization = db.Column(db.JSON)
    properties = db.Column(db.JSON)
    region = db.Column(db.String(64), index=True, nullable=False)
    organization = db.relationship("Organization")
    version = db.Column(db.Integer, default=1, nullable=False)

    def __repr__(self):
        return '<Field {}>'.format(self.name)

class SpecState(enum.Enum):
    offline = 0
    online  = 1 # 只有审核通过以后才能够上线

    def __str__(self):
        return self.name

class Spec(Base, TimestampMixin):
    __tablename__ = 'specs'

    __table_args__ = (
        UniqueConstraint('namespace', 'canonical_name', 'region', 'version'),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), index=True)
    canonical_name = db.Column(db.String(64), index=True, nullable=False)
    namespace = db.Column(db.String(64), db.ForeignKey('organizations.namespace'), nullable=False)
    definition = db.Column(db.JSON)
    introduction = db.Column(MEDIUMTEXT)
    localization = db.Column(db.JSON)
    organization = db.relationship("Organization")
    price = db.Column(db.Integer, nullable=False, default=0)
    properties = db.Column(db.JSON)   # 用来应用场景,更新频率等信息
    public = db.Column(db.Boolean, nullable=False, default=True)
    reference = db.Column(db.String(64), nullable=True, index=True) # canonical_name usually refer to platform
    region = db.Column(db.String(64), index=True, nullable=False)
    state = db.Column(db.Enum(SpecState), nullable=False, default=SpecState.offline, index=True)
    version = db.Column(db.Integer, default=1, nullable=False)
    last_beat_at = db.Column(db.TIMESTAMP)

    def __repr__(self):
        return '<Spec {}>'.format(self.name)

class RequestState(enum.Enum):
    deleted   = 0 # 审核通过以后处于这种状态, 再次提交以后处于reviewing状态
    pending   = 1
    reviewing = 2 # 填写完信息以后处于reviiewing状态
    rejected  = 3 # 审核拒绝以后回到这个状态
    accepted  = 4 # 审核通过以后处于这种状态, 再次提交以后处于reviewing状态

    def __str__(self):
        return self.name

class Request(Base):
    __tablename__ = 'requests'

    id = db.Column(db.Integer, primary_key=True)
    request_type = db.Column(db.String(64), index=True, nullable=False) # change_organization_role | change_spec_definition | change_field_definition
    namespace = db.Column(db.String(64), index=True) # organizations.namespace
    resource = db.Column(db.String(64), index=True, nullable=False)  # users/fields/specs/organizations
    resource_id = db.Column(db.Integer, index=True) 
    content = db.Column(db.JSON)
    comments = db.Column(db.JSON) # comments
    state = db.Column(db.Enum(RequestState), nullable=False, default=RequestState.reviewing, index=True)
    created_by = db.Column(db.Integer, index=True, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.text('CURRENT_TIMESTAMP'))
    accepted_by = db.Column(db.Integer, index=True)
    accepted_at = db.Column(db.TIMESTAMP)

    def __repr__(self):
        return '<Request {}@{}>'.format(self.request_type, self.created_by)

    def delete(self):
        self.state = RequestState.deleted
        self.query.session.add(self)
        self.query.session.commit()
        return self

class Audit(Base):
    __tablename__ = 'audits'

    id = db.Column(db.Integer, primary_key=True)
    resource = db.Column(db.String(64), index=True, nullable=False)
    resource_id = db.Column(db.Integer, index=True, nullable=False)
    operation = db.Column(db.String(256), index=True, nullable=False)
    event = db.Column(db.JSON)
    reference = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.text('CURRENT_TIMESTAMP'))

    def __repr__(self):
        return '<Audit {}>'.format(self.name)
