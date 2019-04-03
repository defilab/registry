from .common import BaseValidator, Failure, OK


class RoleValidator(BaseValidator):
    def __init__(self, *rules):
        super().__init__()
        self._rules = rules

    def validate(self, ctx):
        if not self.applicable(ctx):
            return OK

        for rule in self._rules:
            if rule(ctx):
                return OK

        return Failure(f"user has no permission on the operation")

    @staticmethod
    def admin(ctx):
        if ctx.role in ['super', 'admin']:
            return OK
        return Failure()

