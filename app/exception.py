class RegistryException(Exception):
    status_code = 400

    def __init__(self, message=None, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['error'] = self.__class__.__name__
        if self.message:
            rv['message'] = self.message
        return rv


class InvalidScope(RegistryException):
    pass


class AuthorizeError(RegistryException):
    status_code = 401


class NotAuthorized(AuthorizeError):
    pass


class MissingSignParameters(AuthorizeError):
    pass


class NotFoundCert(AuthorizeError):
    pass


class TimestampExpired(AuthorizeError):
    pass


class BasicAuthFailed(AuthorizeError):
    pass


class InvalidSignature(AuthorizeError):
    pass


class InvalidAuthorizationMethod(AuthorizeError):
    pass


class InvalidAuthorizationHeader(AuthorizeError):
    pass


class MissingAuthorizationHeader(AuthorizeError):
    pass


class UnsupportedHttpMethod(AuthorizeError):
    pass


class BadRequest(RegistryException):
    pass


class ShouldNotUpdateReadOnlyColumn(BadRequest):
    pass


class AlreadyHaveActiveCert(BadRequest):
    pass


class InvalidEmailAddress(BadRequest):
    pass


class PasswordNotMatch(BadRequest):
    pass


class AccountLocked(BadRequest):
    pass


class UserAlreadyHaveOrganization(BadRequest):
    pass


class AlreadyHaveRequestInProcess(BadRequest):
    pass


class NowAllowUpdateReviewingRequest(BadRequest):
    pass


class NotFound(BadRequest):
    pass


class RequestHasBeenAccepted(BadRequest):
    pass


class AlreadyExists(BadRequest):
    pass
