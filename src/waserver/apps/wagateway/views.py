import logging

from jsonrpc import jsonrpc_method
from jsonrpc.site import JsonRpcSite

from waserver.apps.wagateway.core import get_public_authenticator, set_public_authenticator, submit_decryption_request, \
    list_wadevice_decryption_requests, list_authenticator_decryption_requests, reject_decryption_request, \
    accept_decryption_request

from waserver.utils import convert_exceptions_to_jsonrpc_status_slugs, ExtendedDjangoJSONEncoder

logger = logging.getLogger(__name__)

wagateway_extended_jsonrpc_site = JsonRpcSite(json_encoder=ExtendedDjangoJSONEncoder)


@jsonrpc_method("get_public_authenticator", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def get_public_authenticator_view(self, keystore_uid, keystore_secret=None):
    return get_public_authenticator(keystore_uid, keystore_secret=keystore_secret)


@jsonrpc_method("set_public_authenticator", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def set_public_authenticator_view(self, keystore_owner, keystore_uid, keystore_secret, public_keys):
    return set_public_authenticator(keystore_owner=keystore_owner, keystore_uid=keystore_uid,
                                    keystore_secret=keystore_secret,
                                    public_keys=public_keys)


# FIXME : description -> request_description, keystore_uid -> authenticator_keystore_uid, symkeys_data_to_decrypt -> symkey_decryption_requests OK
@jsonrpc_method("submit_decryption_request", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def submit_decryption_request_view(self, authenticator_keystore_uid, requester_uid, description, response_public_key,
                                   response_keychain_uid, response_key_algo, symkey_decryption_requests):
    return submit_decryption_request(authenticator_keystore_uid=authenticator_keystore_uid, requester_uid=requester_uid, description=description,
                                     response_public_key=response_public_key,
                                     response_keychain_uid=response_keychain_uid, response_key_algo=response_key_algo,
                                     symkey_decryption_requests=symkey_decryption_requests)  # FIXME weird name OK


@jsonrpc_method("list_wadevice_decryption_requests", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def list_wadevice_decryption_requests_view(self, requester_uid):
    return list_wadevice_decryption_requests(requester_uid=requester_uid)


@jsonrpc_method("list_authenticator_decryption_requests", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def list_authenticator_decryption_requests_view(self, authenticator_keystore_uid, authenticator_keystore_secret):
    return list_authenticator_decryption_requests(authenticator_keystore_uid=authenticator_keystore_uid, authenticator_keystore_secret=authenticator_keystore_secret)


@jsonrpc_method("reject_decryption_request", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def reject_decryption_request_view(self, authenticator_keystore_secret, decryption_request_uid):
    return reject_decryption_request(authenticator_keystore_secret=authenticator_keystore_secret, decryption_request_uid=decryption_request_uid)


@jsonrpc_method("accept_decryption_request", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def accept_decryption_request_view(self, authenticator_keystore_secret, decryption_request_uid, symkey_decryption_results):
    return accept_decryption_request(authenticator_keystore_secret=authenticator_keystore_secret, decryption_request_uid=decryption_request_uid, symkey_decryption_results=symkey_decryption_results)

