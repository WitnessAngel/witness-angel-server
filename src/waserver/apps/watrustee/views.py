
import logging


from jsonrpc import jsonrpc_method
from jsonrpc.site import JsonRpcSite

from waserver.apps.watrustee.core import SQL_TRUSTEE_API
from waserver.utils import convert_exceptions_to_jsonrpc_status_slugs, ExtendedDjangoJSONEncoder

logger = logging.getLogger(__name__)


watrustee_extended_jsonrpc_site = JsonRpcSite(json_encoder=ExtendedDjangoJSONEncoder)


@jsonrpc_method("fetch_public_key", site=watrustee_extended_jsonrpc_site)
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


@jsonrpc_method("get_message_signature", site=watrustee_extended_jsonrpc_site)
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


@jsonrpc_method("decrypt_with_private_key", site=watrustee_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def decrypt_with_private_key(request, keychain_uid, cipher_algo, cipherdict, passphrases=None, cryptainer_metadata=None):
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
        cryptainer_metadata=cryptainer_metadata,
    )


@jsonrpc_method("request_decryption_authorization", site=watrustee_extended_jsonrpc_site)
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

