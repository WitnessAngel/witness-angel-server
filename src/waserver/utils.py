import base64
import builtins
import logging

from rest_framework.renderers import JSONRenderer as DRFJSONRenderer
from rest_framework.utils.encoders import JSONEncoder as DRFJSONEncoder

import jsonrpc
from decorator import decorator
from django.core.serializers.json import DjangoJSONEncoder
from django.views.decorators.csrf import csrf_exempt
from jsonrpc.site import JsonRpcSite

from wacryptolib import exceptions as wacryptolib_exceptions
from wacryptolib.error_handling import StatusSlugsMapper


# This is for the REST API only #
from wacryptolib.exceptions import FunctionalError
from wacryptolib.utilities import load_from_json_str, dump_to_json_str


class ExtendedDRFJSONEncoder(DRFJSONEncoder):

    def default(self, o):
        if isinstance(o, bytes):
            # Use B64 instead of brutal ASCII bytes.decode()
            # Beware, convert to str else INFINITE LOOP!
            res =  base64.b64encode(o).decode("ascii")
            return res
        return super().default(o)


class ExtendedDRFJSONRenderer(DRFJSONRenderer):
    encoder_class = ExtendedDRFJSONEncoder


#This is for the JSON-RPC service #

# MONKEY-PATCH django-jsonrpc package so that it uses Extended Json in CANONICAL form on responses
from jsonrpc import site

assert site.loads
site.loads = load_from_json_str
assert site.dumps
site.dumps = dump_to_json_str


class ExtendedDjangoJSONEncoder(DjangoJSONEncoder):
    def default(self, o):
        try:
            return super().default(o)
        except TypeError:
            return (
                    "<BROKEN JSON OBJECT FOR %s>" % o
            )  # Just to please jsonrpc _response_dict() method...


# Fix empty GET call case case
_legacy_validate_get = JsonRpcSite._validate_get
JsonRpcSite._validate_get = lambda *args, **kwargs: _legacy_validate_get(*args, **kwargs) or (False, None)

# Fix wrong content type
_legacy_dispatch = JsonRpcSite.dispatch


def bugfixed_dispatched(*args, **kwargs):
    res = _legacy_dispatch(*args, **kwargs)
    res['Content-Type'] = "application/json"  # Else ERR_INVALID_RESPONSE in browser
    return res


JsonRpcSite.dispatch = csrf_exempt(bugfixed_dispatched)


# ONLY list FunctionalError subclasses, not python built-in exceptions!
_exception_classes = StatusSlugsMapper.gather_exception_subclasses(
    wacryptolib_exceptions, parent_classes=[wacryptolib_exceptions.FunctionalError]
)

exception_mapper = StatusSlugsMapper(
    _exception_classes, fallback_exception_class=Exception
)


@decorator
def convert_exceptions_to_jsonrpc_status_slugs(f, *args, **kwargs):
    try:
        return f(*args, **kwargs)
    except FunctionalError as exc:
        status_slugs = exception_mapper.slugify_exception_class(exc.__class__)
        jsonrpc_error = jsonrpc.Error(
            "Server-side exception occurred, see error data for details"
        )
        jsonrpc_error.code = 400  # Unique for now
        jsonrpc_error.status = 200  # Do not trigger nasty errors in rpc client
        jsonrpc_error.data = dict(
            status_slugs=status_slugs,
            data=None,
            message_translated=None,
            message_untranslated=str(exc),
        )
        raise jsonrpc_error from exc
