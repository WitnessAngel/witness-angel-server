# This file is part of Witness Angel Server
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import inspect

import base64
import functools
import jsonrpc
from decorator import decoratorx
from django.core.serializers.json import DjangoJSONEncoder
from django.views.decorators.csrf import csrf_exempt
from jsonrpc.site import JsonRpcSite
from rest_framework.renderers import JSONRenderer as DRFJSONRenderer
from rest_framework.utils.encoders import JSONEncoder as DRFJSONEncoder

from wacryptolib import exceptions as wacryptolib_exceptions
from wacryptolib.error_handling import StatusSlugMapper

# This is for the REST API only #
from wacryptolib.utilities import load_from_json_str, dump_to_json_str


class ExtendedDRFJSONEncoder(DRFJSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            # Use B64 instead of brutal ASCII bytes.decode()
            # Beware, convert to str else INFINITE LOOP!
            res = base64.b64encode(o).decode("ascii")
            return res
        return super().default(o)


class ExtendedDRFJSONRenderer(DRFJSONRenderer):
    encoder_class = ExtendedDRFJSONEncoder


# This is for the JSON-RPC service #

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
            return "<BROKEN JSON OBJECT FOR %s>" % o  # Just to please jsonrpc _response_dict() method...


# Fix empty GET call case case
_legacy_validate_get = JsonRpcSite._validate_get
JsonRpcSite._validate_get = lambda *args, **kwargs: _legacy_validate_get(*args, **kwargs) or (False, None)

# Fix wrong content type
_legacy_dispatch = JsonRpcSite.dispatch


def bugfixed_dispatched(*args, **kwargs):
    res = _legacy_dispatch(*args, **kwargs)
    res["Content-Type"] = "application/json"  # Else ERR_INVALID_RESPONSE in browser
    return res


JsonRpcSite.dispatch = csrf_exempt(bugfixed_dispatched)


# ONLY list FunctionalError subclasses, not python built-in exceptions!
_exception_classes = StatusSlugMapper.gather_exception_subclasses(
    wacryptolib_exceptions, parent_classes=[wacryptolib_exceptions.FunctionalError]
)

exception_mapper = StatusSlugMapper(_exception_classes, fallback_exception_class=Exception)


@decoratorx  # IMPORTANT, because standard "@decorator" changes the argument dispatch!
def convert_exceptions_to_jsonrpc_status_slugs(f, *args, **kwargs):
    try:
        return f(*args, **kwargs)
    except wacryptolib_exceptions.FunctionalError as exc:
        status_slugs = exception_mapper.slugify_exception_class(exc.__class__)
        jsonrpc_error = jsonrpc.Error("Server-side exception occurred, see error data for details")
        jsonrpc_error.code = 400  # Unique for now
        jsonrpc_error.status = 200  # Do not trigger nasty errors in rpc client
        jsonrpc_error.data = dict(
            status_slugs=status_slugs, data=None, message_translated=None, message_untranslated=str(exc)
        )
        raise jsonrpc_error from exc


# We can't use decorator module, because we want a TOLERANT callable here!
def validate_input_parameters(f):
    """Must be applied JUST BEFORE the actual function, to see its real signature."""

    signature = inspect.signature(f)

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if len(args) > 1:  # First parameter is always the WSGI request
            raise wacryptolib_exceptions.ValidationError(
                "Json-Rpc parameters must be passed as keyword arguments for this API, not by position"
            )
        try:
            signature.bind(*args, **kwargs)
        except TypeError as exc:
            raise wacryptolib_exceptions.ValidationError("Incorrect input arguments (%s)" % exc) from exc
        return f(*args, **kwargs)

    return wrapper
