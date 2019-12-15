import random
import sys

from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.key_generation import SUPPORTED_ASYMMETRIC_KEY_TYPES
from wacryptolib.utilities import generate_uuid0


def fuzz():
    jsonrpc_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000/json/"
    escrow_proxy = JsonRpcProxy(url=jsonrpc_url, response_error_handler=status_slugs_response_error_handler)

    for i in range(100):
        keychain_uid = generate_uuid0()
        key_encryption_algo = random.choice(SUPPORTED_ASYMMETRIC_KEY_TYPES)
        print("Fetching key of type %s... " % key_encryption_algo, end="")
        escrow_proxy.get_public_key(keychain_uid=keychain_uid, key_type=key_encryption_algo)
        print("DONE")


if __name__ == '__main__':
    fuzz()
