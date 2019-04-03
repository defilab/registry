from functools import partial
from itertools import chain
from .common import Failure, OK, ScopedValidator


class AttrValidator(ScopedValidator):

    def allow(self, *items, require=None):
        require = () if require is None else require

        def fn(ctx, data):
            allowed = chain(items, require)
            attrs = {item for item in allowed if not callable(item)}
            if attrs:
                invalids = data.keys() - attrs
                if invalids:
                    return Failure(f'not allow {invalids}')

            callbacks = [item for item in allowed if callable(item)]
            for callback in callbacks:
                ok = callback(ctx, data)
                if not ok:
                    return Failure(f'not allow on fn {callback.__name__}')
            return OK

        self.require(*require)
        self._rules.append(fn)
        return self

    def exact(self, *attrs):
        def fn(ctx, data):
            invalids = set(attrs) ^ data.keys()
            if invalids:
                return Failure(f'break exact {attrs}')
            return OK
        self._rules.append(fn)
        return self

    def forbid(self, *attrs):
        def fn(ctx, data):
            invalids = set(attrs) & data.keys()
            if invalids:
                return Failure(f'forbid {invalids}')
            return OK
        self._rules.append(fn)
        return self

    def require(self, *items, nullable=True):
        def fn(ctx, data):
            attrs = { item for item in items if not callable(item) }
            if attrs:
                invalids = attrs - data.keys()
                if invalids:
                    return Failure(f'require {invalids}')
                if not nullable and not all(map(partial(getattr, data), attrs)):
                    return Failure(f'require all {attrs} have none zero value')

            callbacks = [item for item in items if callable(item)]
            for callback in callbacks:
                ok = callback(ctx, data)
                if not ok:
                    return Failure(f'require not satisfy due to {ok.message} fail')
            return OK
        self._rules.append(fn)
        return self
