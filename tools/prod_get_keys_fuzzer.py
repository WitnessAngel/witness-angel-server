import random
import sys

from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.keygen import SUPPORTED_ASYMMETRIC_KEY_ALGOS
from wacryptolib.utilities import generate_uuid0


def fuzz():
    jsonrpc_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000/json/"
    trustee_proxy = JsonRpcProxy(
        url=jsonrpc_url, response_error_handler=status_slugs_response_error_handler
    )

    for i in range(100):
        keychain_uid = generate_uuid0()
        key_cipher_algo = random.choice(SUPPORTED_ASYMMETRIC_KEY_ALGOS)
        print("Fetching key of type %s... " % key_cipher_algo, end="")
        trustee_proxy.fetch_public_key(
            keychain_uid=keychain_uid, key_algo=key_cipher_algo
        )
        print("DONE")


if __name__ == "__main__":
    fuzz()
