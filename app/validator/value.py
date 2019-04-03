from .common import Attr, ScopedValidator


class ValueValidator(ScopedValidator):
    def ensure(self, **kwargs):
        for attr, item in kwargs.items():
            if callable(item):
                rule = Attr(attr).rules(item)
            else:
                rule = Attr(attr).eq(item)
            self._rules.append(rule)
        return self
