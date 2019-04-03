from .role import RoleValidator


class RegistryRoleValidator(RoleValidator):
    @staticmethod
    def admin(ctx):
        return ctx.namespace == 'platform'

    @staticmethod
    def owner(owner_type='namespace'):
        def wrapper(ctx):
            if owner_type == 'namespace':
                return (
                        'namespace' in ctx.request.view_args and
                        ctx.request.view_args['namespace'] == ctx.namespace
                )
            elif owner_type == 'user':
                return (
                        'user_id' in ctx.request.view_args and
                        ctx.request.view_args['user_id'] == ctx.user_id
                )
        return wrapper

    @staticmethod
    def sdk(ctx):
        return ctx.client == 'sdk'

    @staticmethod
    def user(ctx):
        return ctx.client == 'user'
