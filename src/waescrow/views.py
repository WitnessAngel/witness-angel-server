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

from wacryptolib.error_handling import StatusSlugsMapper
from wacryptolib.utilities import load_from_json_str, dump_to_json_str
from waescrow.escrow import SQL_ESCROW_API

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


extended_jsonrpc_site = JsonRpcSite(json_encoder=ExtendedDjangoJSONEncoder)


# TODO refine translated exceptions later
exception_classes = StatusSlugsMapper.gather_exception_subclasses(
    builtins, parent_classes=[Exception]
)
exception_mapper = StatusSlugsMapper(
    exception_classes, fallback_exception_class=Exception
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


@jsonrpc_method("get_public_key", site=extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def get_public_key(request, keychain_uid, key_type):
    logger.info(
        "Got webservice request on get_public_key() for key type %s and keychain uid %s",
        key_type,
        keychain_uid,
    )
    del request
    return SQL_ESCROW_API.get_public_key(keychain_uid=keychain_uid, key_type=key_type)


@jsonrpc_method("get_message_signature", site=extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def get_message_signature(request, keychain_uid, message, signature_algo):
    logger.info(
        "Got webservice request on get_message_signature() for signature algo %s and keychain uid %s",
        signature_algo,
        keychain_uid,
    )
    del request
    return SQL_ESCROW_API.get_message_signature(
        keychain_uid=keychain_uid, message=message, signature_algo=signature_algo
    )


@jsonrpc_method("decrypt_with_private_key", site=extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def decrypt_with_private_key(request, keychain_uid, encryption_algo, cipherdict):
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
    )


@jsonrpc_method("request_decryption_authorization", site=extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def request_decryption_authorization(request, keypair_identifiers, request_message):
    logger.info(
        "Got webservice request on request_decryption_authorization() for %s keypairs with message %r",
        len(keypair_identifiers),
        request_message,
    )
    del request
    return SQL_ESCROW_API.request_decryption_authorization(
        keypair_identifiers=keypair_identifiers, request_message=request_message
    )


@csrf_exempt
def crashdump_report_view(request):

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
