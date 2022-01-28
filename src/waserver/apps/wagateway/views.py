
import logging

from jsonrpc import jsonrpc_method
from jsonrpc.site import JsonRpcSite

from waserver.apps.wagateway.core import get_public_authenticator, set_public_authenticator
from waserver.apps.wagateway.models import PublicAuthenticator
from waserver.apps.wagateway.serializers import PublicAuthenticatorSerializer
from waserver.utils import convert_exceptions_to_jsonrpc_status_slugs, ExtendedDjangoJSONEncoder

from rest_framework import viewsets

logger = logging.getLogger(__name__)


wagateway_extended_jsonrpc_site = JsonRpcSite(json_encoder=ExtendedDjangoJSONEncoder)


class PublicAuthenticatorViewSet(viewsets.ModelViewSet):
    queryset = PublicAuthenticator.objects.all()
    serializer_class = PublicAuthenticatorSerializer


@jsonrpc_method("get_public_authenticator_view", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def get_public_authenticator_view(self, keystore_uid, keystore_secret=None):
    return get_public_authenticator(keystore_uid, keystore_secret=keystore_secret)


@jsonrpc_method("set_public_authenticator_view", site=wagateway_extended_jsonrpc_site)
@convert_exceptions_to_jsonrpc_status_slugs
def set_public_authenticator_view(self, keystore_owner, keystore_uid, keystore_secret, public_keys):
    return set_public_authenticator(keystore_owner=keystore_owner, keystore_uid=keystore_uid,
                                    keystore_secret=keystore_secret,
                                    public_keys=public_keys)
