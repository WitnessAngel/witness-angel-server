import logging

from jsonrpc import jsonrpc_method
from jsonrpc.site import JsonRpcSite

from waserver.apps.wagateway.core import get_public_authenticator, set_public_authenticator, \
    submit_revelation_request, list_wadevice_revelation_requests, \
    list_authenticator_revelation_requests, reject_revelation_request, accept_revelation_request

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


@jsonrpc_method("submit_decryption_request", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def submit_decryption_request_view(self, authenticator_keystore_uid, requester_uid, revelation_request_description, revelation_response_public_key,
                                   revelation_response_keychain_uid, revelation_response_key_algo, symkey_decryption_requests):
    return submit_revelation_request(authenticator_keystore_uid=authenticator_keystore_uid, requester_uid=requester_uid,
                                     revelation_request_description=revelation_request_description,
                                     revelation_response_public_key=revelation_response_public_key,
                                     revelation_response_keychain_uid=revelation_response_keychain_uid,
                                     revelation_response_key_algo=revelation_response_key_algo,
                                     symkey_decryption_requests=symkey_decryption_requests)


@jsonrpc_method("list_wadevice_decryption_requests", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def list_wadevice_revelation_requests_view(self, requester_uid):
    return list_wadevice_revelation_requests(requester_uid=requester_uid)


@jsonrpc_method("list_authenticator_decryption_requests", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def list_authenticator_decryption_requests_view(self, authenticator_keystore_uid, authenticator_keystore_secret):
    return list_authenticator_revelation_requests(authenticator_keystore_uid=authenticator_keystore_uid, authenticator_keystore_secret=authenticator_keystore_secret)


@jsonrpc_method("reject_decryption_request", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def reject_revelation_request_view(self, authenticator_keystore_secret, revelation_request_uid):
    return reject_revelation_request(authenticator_keystore_secret=authenticator_keystore_secret, revelation_request_uid=revelation_request_uid)


@jsonrpc_method("accept_decryption_request", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def accept_revelation_request_view(self, authenticator_keystore_secret, revelation_request_uid, symkey_decryption_results):
    return accept_revelation_request(authenticator_keystore_secret=authenticator_keystore_secret, revelation_request_uid=revelation_request_uid, symkey_decryption_results=symkey_decryption_results)

