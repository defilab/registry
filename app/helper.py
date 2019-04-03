import itertools
from functools import wraps
from flask import request
from .exception import BadRequest

def paginate(query, callback=None):
    resources = query.paginate(request.page, request.page_size)
    if callback:
        items = callback(resources.items)
    else:
        items = [item.to_dict() for item in resources.items]
    data = {
        'items': items,
        'meta': {
            'page': request.page,
            'page_size': request.page_size,
            'total_pages': resources.pages,
            'total_items': resources.total
        },
    }
    return data

def flatten(items):
    return list(itertools.chain.from_iterable(items))

def extract_space_and_name(canonical_name):
    parts = canonical_name.split('.')
    if len(parts) == 1:
        return None, canonical_name
    elif len(parts) == 2:
        return parts[0], parts[1]
    else:
        raise BadRequest('invalid canonical_name')
