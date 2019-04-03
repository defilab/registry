from copy import deepcopy
from functools import partial, reduce, wraps
import operator
import re
from .helper import iterable
from ..exception import BadRequest, InvalidScope


def validate(*validators):
    def decorator(fn):
        @wraps(fn)
        def wrapper(ctx, *args, **kwargs):
            for validator in validators:
                ok = validator.validate(ctx)
                if not ok:
                    raise BadRequest(ok.message)
            return fn(ctx, *args, **kwargs)
        return wrapper
    return decorator


class Result:
    def __init__(self, success, message=None):
        self.success = success
        self.message = message

    def __bool__(self):
        return self.success


class Failure(Result):
    def __init__(self, message=None):
        super().__init__(False, message)


OK = Result(True)

###############################
# Validators
###############################


class ScopedValidatorFactory:
    def __init__(self, cls):
        self.cls = cls

    def __call__(self, scope):
        return self.cls(scope)

    def __getattr__(self, attr):
        return getattr(self.cls('body'), attr)


class BaseValidator:
    def __init__(self):
        self._applicable = None
        self._rules = []
        self._stages = []

    def on(self, fn):
        self._applicable = fn
        return self

    def rules(self, *rules):
        self._rules.extend(rules)
        return self

    def stages(self, *stages):
        self._stages = stages
        return self

    def applicable(self, ctx):
        # stages有值且包含当前应用的环境时规则才生效, 无stages则对所有staging生效
        if self._stages and ctx.app.stage not in self._stages:
            return False

        # 当前请求不满足条件
        if self._applicable:
            return self._applicable(ctx, self.scoped_data(ctx))

        return True

    def validate(self, ctx):
        if not self.applicable(ctx):
            return OK

        for rule in self._rules:
            ok = rule(ctx)
            if not ok:
                return Failure()
        return OK


class ScopedValidator(BaseValidator):
    def __init__(self, scope):
        super().__init__()
        self._roles = []
        self._scope = scope
        self._transforms = []

    def __call__(self, scope):
        self._scope = scope
        return self

    def scoped_data(self, ctx):
        if self._scope == 'body':
            return ctx.request.json
        elif self._scope == 'path':
            return ctx.request.view_args
        elif self._scope == 'query':
            return ctx.request.args
        else:
            raise InvalidScope(f'unsupported scope: {self._scope}')

    def roles(self, *roles):
        self._roles = roles
        return self

    def transform(self, callback=None, **kwargs):
        def helper(attr, fn, data):
            data[attr] = fn(data[attr])

        if callback:
            self._transforms.append(callback)

        for attr, fn in kwargs.items():
            self._transforms.append(partial(helper, attr, fn))
        return self

    def applicable(self, ctx):
        if self._roles and ctx.role not in self._roles:
            return False

        return super().applicable(ctx)

    def validate(self, ctx):
        if not self.applicable(ctx):
            return OK

        data = deepcopy(self.scoped_data(ctx))

        for transform in self._transforms:
            transform(data)

        for rule in self._rules:
            ok = rule(ctx, data)
            if not ok:  # 验证失败
                return Failure(f'{ok.message} in {self._scope}')
        return OK

###############################
# Functions
###############################


class Function:
    def __and__(self, other):
        return And(self, other)

    def __or__(self, other):
        return Or(self, other)

    def __call__(self, *args, **kwargs):
        raise NotImplementedError()


class And(Function):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def __call__(self, *args, **kwargs):
        ok = self.left(*args, **kwargs)
        if not ok:
            return ok
        return self.right(*args, **kwargs)


class Or(Function):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def __call__(self, *args, **kwargs):
        if self.left(*args, **kwargs):
            return OK
        return self.right(*args, **kwargs)


###############################
# Attribute Helper Methods
###############################


class Group(Function):
    def __init__(self, *attrs, absentable=False):
        self.attrs = set(attrs)
        self.absentable = absentable

    def __call__(self, ctx, data):
        cnt = len(self.attrs - data.keys())
        if (self.absentable and cnt in [0, len(self.attrs)]) or (not self.absentable and cnt == 0):
            return OK
        return Failure(f'not match group {self.attrs}')


class Groups(Function):
    def __init__(self, *groups, mutex=True):
        self.groups = groups
        self.mutex = mutex

    def __call__(self, ctx, data):
        if self.mutex:
            cnt = [len(set(x) - data.keys()) > 0 for x in self.groups].count(True)
            if cnt <= 0:
                return Failure(f'not match any group {self.groups}')
            elif cnt > 1:
                return Failure(f'conflicts groups {self.groups}')
        combined = reduce(operator.or_, map(Group, self.groups))
        return combined(ctx, data)

###############################
# Value Helper Methods
###############################


class Operator(Function):
    def __init__(self, target):
        self.target = target


class Comparator(Operator):
    def __init__(self, op, target):
        super().__init__(target)
        self.op = op

    def __call__(self, val):
        if self.op(val, self.target):
            return OK
        return Failure(f'break {self.op.__name__}({self.target})')


Lt = partial(Comparator, operator.lt)
Eq = partial(Comparator, operator.eq)


class In(Function):
    def __init__(self, *options):
        self.options = options

    def __call__(self, val):
        items = val if iterable(val) else [val]
        for item in items:
            if val not in self.options:
                return Failure(f'{item} not in {self.options}')
        return OK


class Not(Function):
    def __init__(self, fn):
        self.fn = fn

    def __call__(self, *args, **kwargs):
        if self.fn(*args, **kwargs):
            return Failure(f'{self.fn.__name__} is True')
        return OK


class Match(Function):
    def __init__(self, pattern):
        self.pattern = pattern

    def __call__(self, val):
        if not re.match(self.pattern, val):
            return Failure(f'{val} not match {self.pattern}')
        return OK


class Attr(Function):
    def __init__(self, *attrs):
        self._attrs = attrs
        self._rules = []

    def __call__(self, ctx, data):
        for attr in self._attrs:
            if attr not in data:
                return Failure(f"'{attr}' is absent")
            for rule in self._rules:
                ok = rule(data[attr])
                if not ok:
                    return Failure(f"'{attr}' {ok.message}")
        return OK

    def __getattr__(self, name):
        if name in ['eq', 'ge', 'gt', 'is_', 'is_not', 'le', 'lt', 'ne', 'not_']:
            return partial(self._cmp, getattr(operator, name))
        raise AttributeError(f"'Value' object has no attribute '{name}'")

    def _cmp(self, op, target):
        return self.rules(Comparator(op, target))

    def in_(self, *options):
        return self.rules(In(*options))

    def match(self, pattern):
        return self.rules(Match(pattern))

    def rules(self, *rules):
        self._rules.extend(rules)
        return self

    @staticmethod
    def has(*attrs):
        def wrapper(ctx, data):
            missing = set(attrs) - data.keys()
            if missing:
                return Failure(f'miss {missing}')
            return OK
        return wrapper

