import logging

from jsonrpc import jsonrpc_method
from jsonrpc.site import JsonRpcSite

from waserver.apps.wagateway.core import (
    get_public_authenticator,
    set_public_authenticator,
    submit_revelation_request,
    list_requestor_revelation_requests,
    list_authenticator_revelation_requests,
    reject_revelation_request,
    accept_revelation_request,
)
from waserver.utils import (
    convert_exceptions_to_jsonrpc_status_slugs,
    ExtendedDjangoJSONEncoder,
    validate_input_parameters,
)

logger = logging.getLogger(__name__)

wagateway_extended_jsonrpc_site = JsonRpcSite(json_encoder=ExtendedDjangoJSONEncoder)


@jsonrpc_method("get_public_authenticator", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
@validate_input_parameters
def get_public_authenticator_view(request, keystore_uid, keystore_secret=None):
    return get_public_authenticator(keystore_uid, keystore_secret=keystore_secret)


@jsonrpc_method("set_public_authenticator", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
@validate_input_parameters
def set_public_authenticator_view(request, keystore_uid, keystore_owner, public_keys, keystore_secret,
                                  keystore_creation_datetime=None):
    return set_public_authenticator(
        keystore_uid=keystore_uid,
        keystore_owner=keystore_owner,
        public_keys=public_keys,
        keystore_secret=keystore_secret,
        keystore_creation_datetime=keystore_creation_datetime
    )


@jsonrpc_method("submit_revelation_request", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
@validate_input_parameters
def submit_decryption_request_view(
    request,
    authenticator_keystore_uid,
    revelation_requestor_uid,
    revelation_request_description,
    revelation_response_public_key,
    revelation_response_keychain_uid,
    revelation_response_key_algo,
    symkey_decryption_requests,
):
    return submit_revelation_request(
        authenticator_keystore_uid=authenticator_keystore_uid,
        revelation_requestor_uid=revelation_requestor_uid,
        revelation_request_description=revelation_request_description,
        revelation_response_public_key=revelation_response_public_key,
        revelation_response_keychain_uid=revelation_response_keychain_uid,
        revelation_response_key_algo=revelation_response_key_algo,
        symkey_decryption_requests=symkey_decryption_requests,
    )


@jsonrpc_method("list_requestor_revelation_requests", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
@validate_input_parameters
def list_requestor_revelation_requests_view(request, revelation_requestor_uid):
    return list_requestor_revelation_requests(revelation_requestor_uid=revelation_requestor_uid)


@jsonrpc_method("list_authenticator_revelation_requests", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
@validate_input_parameters
def list_authenticator_decryption_requests_view(request, authenticator_keystore_uid, authenticator_keystore_secret):
    return list_authenticator_revelation_requests(
        authenticator_keystore_uid=authenticator_keystore_uid,
        authenticator_keystore_secret=authenticator_keystore_secret,
    )


@jsonrpc_method("reject_revelation_request", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
@validate_input_parameters
def reject_revelation_request_view(request, revelation_request_uid, authenticator_keystore_secret):
    return reject_revelation_request(
        revelation_request_uid=revelation_request_uid, authenticator_keystore_secret=authenticator_keystore_secret
    )


@jsonrpc_method("accept_revelation_request", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
@validate_input_parameters
def accept_revelation_request_view(
    request, revelation_request_uid, symkey_decryption_results, authenticator_keystore_secret
):
    return accept_revelation_request(
        revelation_request_uid=revelation_request_uid,
        symkey_decryption_results=symkey_decryption_results,
        authenticator_keystore_secret=authenticator_keystore_secret,
    )
