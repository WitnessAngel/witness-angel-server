import builtins
import logging

import jsonrpc
from decorator import decorator
from django.conf import settings
from django.core.serializers.json import DjangoJSONEncoder
from django.http import HttpResponse, HttpResponseBadRequest
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from jsonrpc import jsonrpc_method
from jsonrpc.site import JsonRpcSite
from rest_framework import viewsets

from wacryptolib import exceptions as wacryptolib_exceptions
from wacryptolib.error_handling import StatusSlugsMapper
from wacryptolib.utilities import load_from_json_str, dump_to_json_str

from waescrow.escrow import SQL_ESCROW_API, get_public_authenticator, set_public_authenticator
from waescrow.models import AuthenticatorUser, AuthenticatorPublicKey
from waescrow.serializers import AuthenticatorUserSerializer

logger = logging.getLogger(__name__)

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

extended_jsonrpc_site = JsonRpcSite(json_encoder=ExtendedDjangoJSONEncoder)

# TODO refine translated exceptions later - FIXME DEDUPLICATE THIS WITH WACRYPTOLIB JSONRPC CLIENT!!!
_exception_classes = StatusSlugsMapper.gather_exception_subclasses(
    builtins, parent_classes=[Exception]
)
_exception_classes += StatusSlugsMapper.gather_exception_subclasses(
    wacryptolib_exceptions, parent_classes=[wacryptolib_exceptions.FunctionalError]
)

exception_mapper = StatusSlugsMapper(
    _exception_classes, fallback_exception_class=Exception
)


@decorator
def convert_exceptions_to_jsonrpc_status_slugs(f, *args, **kwargs):
    try:
        return f(*args, **kwargs)
    except Exception as exc:  # FIXME - do not convert ALL exceptions, some classes are to be unhandled!
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


@jsonrpc_method("fetch_public_key", site=extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def fetch_public_key(request, keychain_uid, key_algo, must_exist=False):
    logger.info(
        "Got webservice request on get_public_key() for key type %s and keychain uid %s (must_exist=%s)",
        key_algo,
        keychain_uid,
        must_exist,
    )
    del request
    return SQL_ESCROW_API.fetch_public_key(keychain_uid=keychain_uid, key_algo=key_algo, must_exist=must_exist)


@jsonrpc_method("get_message_signature", site=extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def get_message_signature(request, keychain_uid, message, payload_signature_algo):
    logger.info(
        "Got webservice request on get_message_signature() for signature algo %s and keychain uid %s",
        payload_signature_algo,
        keychain_uid,
    )
    del request
    return SQL_ESCROW_API.get_message_signature(
        keychain_uid=keychain_uid, message=message, payload_signature_algo=payload_signature_algo
    )


@jsonrpc_method("decrypt_with_private_key", site=extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def decrypt_with_private_key(request, keychain_uid, encryption_algo, cipherdict, passphrases=None):
    logger.info(
        "Got webservice request on decrypt_with_private_key() for encryption algo %s and keychain uid %s",
        encryption_algo,
        keychain_uid,
    )
    del request
    return SQL_ESCROW_API.decrypt_with_private_key(
        keychain_uid=keychain_uid,
        encryption_algo=encryption_algo,
        cipherdict=cipherdict,
        passphrases=passphrases,
    )


@jsonrpc_method("request_decryption_authorization", site=extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def request_decryption_authorization(request, keypair_identifiers, request_message, passphrases=None):
    logger.info(
        "Got webservice request on request_decryption_authorization() for %s keypairs with message %r",
        len(keypair_identifiers),
        request_message,
    )
    del request
    return SQL_ESCROW_API.request_decryption_authorization(
        keypair_identifiers=keypair_identifiers, request_message=request_message, passphrases=passphrases
    )


@csrf_exempt
def crashdump_report_view(request):
    if request.method == "GET":
        return HttpResponse(b"CRASHDUMP ENDPOINT OF WAESCROW")

    crashdump = request.POST.get("crashdump")
    if not crashdump:
        logger.warning("Empty crashdump report received")
        return HttpResponseBadRequest(b"Missing crashdump field")

    filename = timezone.now().strftime("%Y%m%d-%H%M%S-%f.dump")
    logger.info(
        "Got http request on crashdump report view (%s chars), stored in %s",
        len(crashdump),
        filename,
    )

    crashdump_path = settings.CRASHDUMPS_DIR.joinpath(filename)
    crashdump_path.write_text(crashdump, encoding="utf8")
    return HttpResponse(b"OK")


class AuthenticatorUserViewSet(viewsets.ModelViewSet):
    queryset = AuthenticatorUser.objects.all()
    serializer_class = AuthenticatorUserSerializer


@jsonrpc_method("get_public_authenticator_view", site=extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def get_public_authenticator_view(self, username, authenticator_secret):
    return get_public_authenticator(username=username, authenticator_secret=authenticator_secret)


@jsonrpc_method("set_public_authenticator_view", site=extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def set_public_authenticator_view(self, username, description, authenticator_secret, public_keys):
    return set_public_authenticator(username=username, description=description,
                                    authenticator_secret=authenticator_secret,
                                    public_keys=public_keys)
