from .attribute import AttrValidator
from .common import validate, Attr, Eq, Group, In, Lt, Not, ScopedValidatorFactory
from .extention import RegistryRoleValidator
from .value import ValueValidator

attr = ScopedValidatorFactory(AttrValidator)
value = ScopedValidatorFactory(ValueValidator)
roles = RegistryRoleValidator
