from uuid import UUID

import requests

import pytest
from Crypto.Random import get_random_bytes

from wacryptolib.exceptions import KeystoreDoesNotExist, KeystoreAlreadyExists, KeyDoesNotExist, ExistenceError, \
    SchemaValidationError
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.keygen import generate_symkey, generate_keypair, load_asymmetric_key_from_pem_bytestring
from wacryptolib.utilities import generate_uuid0
from waserver.apps.wagateway.core import submit_decryption_request, \
    list_wadevice_decryption_requests, validate_data_tree_with_pythonschema, PUBLIC_AUTHENTICATOR_SCHEMA, \
    list_authenticator_decryption_requests, reject_decryption_request, accept_decryption_request
from waserver.apps.wagateway.models import PublicAuthenticator, RequestStatus, DecryptionStatus

from waserver.apps.wagateway.views import set_public_authenticator_view


def _generate_authenticator_parameter_tree(key_count, key_value=None):
    public_keys = []

    for count in range(key_count):
        public_keys.append({
            "keychain_uid": generate_uuid0(),
            "key_algo": "RSA_OAEP",
            "key_value": key_value or get_random_bytes(20)
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

    gateway_proxy = JsonRpcProxy(
        url=jsonrpc_url, response_error_handler=status_slugs_response_error_handler
    )

    parameters = _generate_authenticator_parameter_tree(2)

    with pytest.raises(KeystoreDoesNotExist):
        gateway_proxy.get_public_authenticator(keystore_uid=parameters["keystore_uid"])

    gateway_proxy.set_public_authenticator(keystore_uid=parameters["keystore_uid"],
                                           keystore_owner=parameters["keystore_owner"],
                                           keystore_secret=parameters["keystore_secret"],
                                           public_keys=parameters["public_keys"])

    with pytest.raises(KeystoreAlreadyExists):
        gateway_proxy.set_public_authenticator(keystore_uid=parameters["keystore_uid"],
                                               keystore_owner=parameters["keystore_owner"],
                                               keystore_secret="whatever",
                                               public_keys=parameters["public_keys"])

    # Check handling of secret hash, similar to a password!
    public_authenticator_obj: PublicAuthenticator = PublicAuthenticator.objects.get(
        keystore_uid=parameters["keystore_uid"])
    _keystore_secret_hash = public_authenticator_obj.keystore_secret_hash
    assert _keystore_secret_hash
    assert _keystore_secret_hash != parameters["keystore_secret"]
    assert _keystore_secret_hash.startswith("pbkdf2_")
    assert public_authenticator_obj.has_usable_keystore_secret()
    assert public_authenticator_obj.check_keystore_secret(parameters["keystore_secret"])
    assert not public_authenticator_obj.check_keystore_secret("whatever")
    public_authenticator_obj.set_unusable_keystore_secret()
    assert not public_authenticator_obj.has_usable_keystore_secret()
    public_authenticator_obj.refresh_from_db()  # Unusable password was NOT saved
    assert public_authenticator_obj.has_usable_keystore_secret()

    public_authenticator = gateway_proxy.get_public_authenticator(keystore_uid=parameters["keystore_uid"])
    del parameters["keystore_secret"]
    assert parameters == public_authenticator

    # check_public_authenticator_sanity(public_authenticator)
    validate_data_tree_with_pythonschema(public_authenticator, PUBLIC_AUTHENTICATOR_SCHEMA)


def test_rest_api_get_public_authenticator(live_server):
    parameters = _generate_authenticator_parameter_tree(2, key_value="aé$£é&ö".encode("utf8"))

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
    # from pprint import pprint
    # pprint(public_authenticator)

    # FIXME later add a new pythonschema for this "raw json" format?
    assert public_authenticator == {'keystore_owner': 'keystore_owner',
                                    'keystore_uid': str(parameters["keystore_uid"]),
                                    # Uses standard string representation of UUIDs
                                    'public_keys': [{'key_algo': 'RSA_OAEP',
                                                     'keychain_uid': str(parameters["public_keys"][0]["keychain_uid"]),
                                                     'key_value': 'YcOpJMKjw6kmw7Y='},
                                                    # Direct base64 is used instead of $binary dict
                                                    {'key_algo': 'RSA_OAEP',
                                                     'keychain_uid': str(parameters["public_keys"][1]["keychain_uid"]),
                                                     'key_value': 'YcOpJMKjw6kmw7Y='}]}


def test_decryption_request(live_server):
    jsonrpc_url = live_server.url + "/gateway/jsonrpc/"

    gateway_proxy = JsonRpcProxy(
        url=jsonrpc_url, response_error_handler=status_slugs_response_error_handler
    )

    parameters1 = _generate_authenticator_parameter_tree(2)
    parameters2 = _generate_authenticator_parameter_tree(2)

    key_algo="RSA_OAEP"

    # Vérifie que les public authenticator n'existe pas sur le server
    with pytest.raises(KeystoreDoesNotExist):  # TODO change this exception to keyDoesNotExist
        gateway_proxy.get_public_authenticator(keystore_uid=parameters1["keystore_uid"])

    with pytest.raises(KeystoreDoesNotExist):  # TODO change this exception to keyDoesNotExist
        gateway_proxy.get_public_authenticator(keystore_uid=parameters2["keystore_uid"])

    # Publier les deux authenticators sur mon server
    gateway_proxy.set_public_authenticator(keystore_uid=parameters1["keystore_uid"],
                                           keystore_owner=parameters1["keystore_owner"],
                                           keystore_secret=parameters1["keystore_secret"],
                                           public_keys=parameters1["public_keys"])

    gateway_proxy.set_public_authenticator(keystore_uid=parameters2["keystore_uid"],
                                           keystore_owner=parameters2["keystore_owner"],
                                           keystore_secret=parameters2["keystore_secret"],
                                           public_keys=parameters2["public_keys"])

    # Recuperer dans une liste tous les publics authenticators
    public_authenticators = []
    public_authenticator1 = gateway_proxy.get_public_authenticator(keystore_uid=parameters1["keystore_uid"])
    public_authenticator2 = gateway_proxy.get_public_authenticator(keystore_uid=parameters2["keystore_uid"])
    public_authenticators.append(public_authenticator1)
    public_authenticators.append(public_authenticator2)

    # Créer la response keypair
    response_keypair = generate_keypair(key_algo=key_algo)

    # Créer la symkey
    symkey_dict = generate_symkey(cipher_algo="AES_CBC")

    for public_authenticator in public_authenticators:
        decryption_request_parameter = {
            "keystore_uid": public_authenticator["keystore_uid"],
            "requester_uid": generate_uuid0(),
            "description": "Bien vouloir nous aider pour le déchiffrement de cette clé.",
            "response_public_key": response_keypair["public_key"],
            "response_keychain_uid": generate_uuid0(),
            "response_key_algo": key_algo,
            "symkeys_data_to_decrypt": [{
                "cryptainer_uid": generate_uuid0(),
                "cryptainer_metadata": {},
                "symkey_ciphertext": symkey_dict["key"],
                "keychain_uid": public_authenticator["public_keys"][0]["keychain_uid"],
                "key_algo": public_authenticator["public_keys"][0]["key_algo"],
            }]
        }

        # Soumettre une demande de déchiffrement
        submit_decryption_request(keystore_uid=decryption_request_parameter["keystore_uid"],
                                  requester_uid=decryption_request_parameter["requester_uid"],
                                  description=decryption_request_parameter["description"],
                                  response_public_key=decryption_request_parameter["response_public_key"],
                                  response_keychain_uid=decryption_request_parameter["response_keychain_uid"],
                                  response_key_algo=decryption_request_parameter["response_key_algo"],
                                  symkeys_data_to_decrypt=decryption_request_parameter["symkeys_data_to_decrypt"])

        # Liste des demandes de déchiffrement par le nvr
        wadevice_decryption_requests = list_wadevice_decryption_requests(
            requester_uid=decryption_request_parameter["requester_uid"])

        assert wadevice_decryption_requests[0]["requester_uid"] == decryption_request_parameter["requester_uid"]
        assert wadevice_decryption_requests[0]["response_public_key"] == decryption_request_parameter["response_public_key"]
        #assert wadevice_decryption_requests[0]["response_keychain_uid"] == UUID(decryption_request_parameter["response_keychain_uid"])
        assert wadevice_decryption_requests[0]["response_key_algo"] == decryption_request_parameter["response_key_algo"]
        assert wadevice_decryption_requests[0]["request_status"] == RequestStatus.PENDING
        """assert wadevice_decryption_requests[0]["symkeys_decryption"] == [{
            'authenticator_public_key': [{
                "keychain_uid": decryption_request_parameter["symkeys_data_to_decrypt"][0]["keychain_uid"],
                "key_algo": decryption_request_parameter["symkeys_data_to_decrypt"][0]["key_algo"],
                "key_value": decryption_request_parameter["symkeys_data_to_decrypt"][0]["keychain_uid"]
        }],
            'cryptainer_uid': decryption_request_parameter["symkeys_data_to_decrypt"][0]["cryptainer_uid"],
            'cryptainer_metadata': decryption_request_parameter["symkeys_data_to_decrypt"][0]["cryptainer_metadata"],
            'request_data': decryption_request_parameter["symkeys_data_to_decrypt"]["symkey_ciphertext"],
            'response_data': b'',
            'decryption_status': DecryptionStatus.PENDING
        }]"""

        # Liste des demandes de déchiffrement par le nvr avec un requester_uid inexistant
        with pytest.raises(ExistenceError):
            list_wadevice_decryption_requests(requester_uid=generate_uuid0())









