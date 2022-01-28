
import requests

import pytest
from Crypto.Random import get_random_bytes

from wacryptolib.exceptions import KeystoreDoesNotExist, KeystoreAlreadyExists
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.utilities import generate_uuid0
from waserver.apps.wagateway.core import check_public_authenticator_sanity

from waserver.apps.wagateway.views import set_public_authenticator_view




def _generate_authenticator_parameter_tree(key_count, payload=None):
    public_keys = []

    for count in range(key_count):
        public_keys.append({
            "keychain_uid": generate_uuid0(),
            "key_algo": "RSA_OAEP",
            "payload": payload or get_random_bytes(20)
        })

    parameters = dict(
        keystore_owner="keystore_owner",
        keystore_secret="keystore_secret",
        keystore_uid=generate_uuid0(),
        public_keys=public_keys
    )
    return parameters


def test_jsonrpc_set_and_get_public_authenticator(live_server):
    jsonrpc_url = live_server.url + "/gateway/jsonrpc/"

    trustee_proxy = JsonRpcProxy(
        url=jsonrpc_url, response_error_handler=status_slugs_response_error_handler
    )

    parameters = _generate_authenticator_parameter_tree(2)

    with pytest.raises(KeystoreDoesNotExist):
        trustee_proxy.get_public_authenticator_view(keystore_uid=parameters["keystore_uid"])

    trustee_proxy.set_public_authenticator_view(keystore_uid=parameters["keystore_uid"],
                                                keystore_owner=parameters["keystore_owner"],
                                                keystore_secret=parameters["keystore_secret"],
                                                public_keys=parameters["public_keys"])

    with pytest.raises(KeystoreAlreadyExists):
        trustee_proxy.set_public_authenticator_view(keystore_uid=parameters["keystore_uid"],
                                                    keystore_owner=parameters["keystore_owner"],
                                                    keystore_secret="whatever",
                                                    public_keys=parameters["public_keys"])

    public_authenticator = trustee_proxy.get_public_authenticator_view(keystore_uid=parameters["keystore_uid"])

    del parameters["keystore_secret"]
    assert parameters == public_authenticator
    check_public_authenticator_sanity(public_authenticator)


def test_rest_api_get_public_authenticator(live_server):
    parameters = _generate_authenticator_parameter_tree(2, payload="aé$£é&ö".encode("utf8"))

    set_public_authenticator_view(None,
                                  keystore_uid=parameters["keystore_uid"],
                                    keystore_owner=parameters["keystore_owner"],
                                    keystore_secret=parameters["keystore_secret"],
                                    public_keys=parameters["public_keys"])

    url = live_server.url + "/gateway/rest/public-authenticators/"
    response = requests.get(url)
    assert response.status_code == 200
    public_authenticators = response.json()
    assert len(public_authenticators) == 1
    public_authenticator = public_authenticators[0]
    #from pprint import pprint
    #pprint(public_authenticator)

    # FIXME later add a new pythonschema for this "raw json" format?
    assert public_authenticator == {'keystore_owner': 'keystore_owner',
     'keystore_uid': str(parameters["keystore_uid"]),  # Uses standard string representation of UUIDs
     'public_keys': [{'key_algo': 'RSA_OAEP',
                      'keychain_uid': str(parameters["public_keys"][0]["keychain_uid"]),
                      'payload': 'YcOpJMKjw6kmw7Y='},  # Direct base64 is used instead of $binary dict
                     {'key_algo': 'RSA_OAEP',
                      'keychain_uid': str(parameters["public_keys"][1]["keychain_uid"]),
                      'payload': 'YcOpJMKjw6kmw7Y='}]}

