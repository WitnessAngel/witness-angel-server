from django.core.serializers.json import DjangoJSONEncoder
from jsonrpc import jsonrpc_method
from jsonrpc.site import JsonRpcSite

from wacryptolib import key_generation

from . import escrow_api

# MONKEY-PATCH django-jsonrpc package so that it uses Extended Json on responses
from bson.json_util import dumps, loads
from jsonrpc import site

assert site.loads
site.loads = loads
assert site.dumps
site.dumps = dumps

class ExtendedDjangoJSONEncoder(DjangoJSONEncoder):
    def default(self, o):
        try:
            return super().default(o)
        except TypeError:
            return "<BROKEN JSON OBJECT FOR %s>" % o  # Just to please jsonrpc _response_dict() method...


extended_jsonrpc_site = JsonRpcSite(json_encoder=ExtendedDjangoJSONEncoder)
"""

@jsonrpc_method("waescrow.sayhelloworld")
def sayhelloworld(request):
    return "Hello world"


@jsonrpc_method("generate_keypair(str) -> str")
def get_public_key(request, algo):
    pem_keypair = key_generation.generate_assymetric_keypair(uid=None, key_type=algo)
    return pem_keypair["public_key"]

"""

@jsonrpc_method("get_public_key", site=extended_jsonrpc_site)
def get_public_key(request, keychain_uid, key_type):
    del request
    return escrow_api.get_public_key(keychain_uid=keychain_uid, key_type=key_type)

@jsonrpc_method("get_message_signature", site=extended_jsonrpc_site)
def get_message_signature(request, keychain_uid, message, key_type, signature_algo):
    del request
    return escrow_api.get_message_signature(
            keychain_uid=keychain_uid, message=message, key_type=key_type, signature_algo=signature_algo
    )

@jsonrpc_method("decrypt_with_private_key", site=extended_jsonrpc_site)
def decrypt_with_private_key(request, keychain_uid, key_type, encryption_algo, cipherdict):
    del request
    return escrow_api.decrypt_with_private_key(
            keychain_uid=keychain_uid,
        key_type=key_type,
        encryption_algo=encryption_algo,
        cipherdict=cipherdict,
    )
