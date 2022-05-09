import logging

from jsonrpc import jsonrpc_method
from jsonrpc.site import JsonRpcSite

from waserver.apps.wagateway.core import get_public_authenticator, set_public_authenticator, submit_decryption_request, \
    list_wadevice_decryption_requests, list_authenticator_decryption_requests, reject_decryption_request, \
    accept_decryption_request
from waserver.apps.wagateway.models import PublicAuthenticator
from waserver.apps.wagateway.serializers import PublicAuthenticatorSerializer
from waserver.utils import convert_exceptions_to_jsonrpc_status_slugs, ExtendedDjangoJSONEncoder

from rest_framework import viewsets

logger = logging.getLogger(__name__)

wagateway_extended_jsonrpc_site = JsonRpcSite(json_encoder=ExtendedDjangoJSONEncoder)


class PublicAuthenticatorViewSet(viewsets.ModelViewSet):
    queryset = PublicAuthenticator.objects.all()
    serializer_class = PublicAuthenticatorSerializer


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
def submit_decryption_request_view(self, keystore_uid, requester_uid, description, response_public_key,
                                   response_keychain_uid, response_key_algo, symkeys_data_to_decrypt):
    return submit_decryption_request(keystore_uid=keystore_uid, requester_uid=requester_uid, description=description,
                                     response_public_key=response_public_key,
                                     response_keychain_uid=response_keychain_uid, response_key_algo=response_key_algo,
                                     symkeys_data_to_decrypt=symkeys_data_to_decrypt)


@jsonrpc_method("list_wadevice_decryption_requests", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def list_wadevice_decryption_requests_view(self, requester_uid):
    return list_wadevice_decryption_requests(requester_uid=requester_uid)


@jsonrpc_method("list_authenticator_decryption_requests", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def list_authenticator_decryption_requests_view(self, keystore_uid):
    return list_authenticator_decryption_requests(keystore_uid=keystore_uid)


@jsonrpc_method("reject_decryption_request", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def reject_decryption_request_view(self, decryption_request_uid):
    return reject_decryption_request(decryption_request_uid=decryption_request_uid)


@jsonrpc_method("accept_decryption_request", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def accept_decryption_request_view(self, decryption_request_uid, symkey_decryptions_result):
    return accept_decryption_request(decryption_request_uid=decryption_request_uid, symkey_decryptions_result=symkey_decryptions_result)

