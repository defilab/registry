from functools import partial, update_wrapper, wraps
from flask import current_app, request, Blueprint, Flask, Request
from flask_sqlalchemy import BaseQuery
from werkzeug.datastructures import TypeConversionDict


class ParameterDict(TypeConversionDict):
    def pop(self, key, default=None, type=None):
        val = self.get(key, default, type)
        super().pop(key, None)
        return val

    def to_dict(self, *args, **kwargs):
        return self


class RegistryRequest(Request):
    parameter_storage_class = ParameterDict

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._parse_common_args()

    def _parse_common_args(self):
        self.page = self.args.pop('page', 1, type=int)
        self.page_size = min(self.args.pop('page_size', 10, type=int), 100)

    @property
    def json(self):
        if self.data:
            return self.get_json(force=True)
        else:
            return {}


class RegistryFlask(Flask):
    request_class = RegistryRequest


class PowerfulQuery(BaseQuery):
    def get_or(self, ident, default=None):
        return self.get(ident) or default


class Context:
    def __init__(self, app, request):
        self.app = app
        self.authorize = {}
        self.namespace = None
        self.user_id = None
        self.client = None
        self.request = request


class RegistryBlueprint(Blueprint):
    def route(self, rule, **options):
        register = super().route(rule, **options)

        def decorator(fn):
            handler = partial(fn, Context(current_app, request))
            update_wrapper(handler, fn)
            return register(handler)

        return decorator
