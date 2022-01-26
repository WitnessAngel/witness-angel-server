
import logging

from django.conf import settings
from django.http import HttpResponse, HttpResponseBadRequest
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from jsonrpc import jsonrpc_method
from wacryptolib.utilities import load_from_json_str, dump_to_json_str

from watrustee.trustee import get_public_authenticator, set_public_authenticator, SQL_TRUSTEE_API
from watrustee.models import PublicAuthenticator
from watrustee.serializers import PublicAuthenticatorSerializer
from watrustee.utils import extended_jsonrpc_site, convert_exceptions_to_jsonrpc_status_slugs

from rest_framework import viewsets

logger = logging.getLogger(__name__)



# MONKEY-PATCH django-jsonrpc package so that it uses Extended Json in CANONICAL form on responses
from jsonrpc import site

assert site.loads
site.loads = load_from_json_str
assert site.dumps
site.dumps = dump_to_json_str


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
    return SQL_TRUSTEE_API.fetch_public_key(keychain_uid=keychain_uid, key_algo=key_algo, must_exist=must_exist)


@jsonrpc_method("get_message_signature", site=extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def get_message_signature(request, keychain_uid, message, signature_algo):
    logger.info(
        "Got webservice request on get_message_signature() for signature algo %s and keychain uid %s",
        signature_algo,
        keychain_uid,
    )
    del request
    return SQL_TRUSTEE_API.get_message_signature(
        keychain_uid=keychain_uid, message=message, signature_algo=signature_algo
    )


@jsonrpc_method("decrypt_with_private_key", site=extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def decrypt_with_private_key(request, keychain_uid, cipher_algo, cipherdict, passphrases=None):
    logger.info(
        "Got webservice request on decrypt_with_private_key() for encryption algo %s and keychain uid %s",
        cipher_algo,
        keychain_uid,
    )
    del request
    return SQL_TRUSTEE_API.decrypt_with_private_key(
        keychain_uid=keychain_uid,
        cipher_algo=cipher_algo,
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
    return SQL_TRUSTEE_API.request_decryption_authorization(
        keypair_identifiers=keypair_identifiers, request_message=request_message, passphrases=passphrases
    )


@csrf_exempt
def crashdump_report_view(request):
    if request.method == "GET":
        return HttpResponse(b"CRASHDUMP ENDPOINT OF WATRUSTEE")

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


class PublicAuthenticatorViewSet(viewsets.ModelViewSet):
    queryset = PublicAuthenticator.objects.all()
    serializer_class = PublicAuthenticatorSerializer


@jsonrpc_method("get_public_authenticator_view", site=extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def get_public_authenticator_view(self, keystore_uid, keystore_secret=None):
    return get_public_authenticator(keystore_uid, keystore_secret=keystore_secret)


@jsonrpc_method("set_public_authenticator_view", site=extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def set_public_authenticator_view(self, keystore_owner, keystore_uid, keystore_secret, public_keys):
    return set_public_authenticator(keystore_owner=keystore_owner, keystore_uid=keystore_uid,
                                    keystore_secret=keystore_secret,
                                    public_keys=public_keys)
