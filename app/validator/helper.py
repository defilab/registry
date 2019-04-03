from collections import Iterable


def iterable(obj):
    return isinstance(obj, Iterable) and not isinstance(obj, (str, bytes, bytearray))
