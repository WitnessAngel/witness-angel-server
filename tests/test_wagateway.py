from uuid import UUID

import requests

import pytest
from Crypto.Random import get_random_bytes

from wacryptolib.exceptions import KeystoreDoesNotExist, KeystoreAlreadyExists, KeyDoesNotExist, ExistenceError, \
    SchemaValidationError
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
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

    parameters = _generate_authenticator_parameter_tree(2)

    with pytest.raises(KeystoreDoesNotExist):  # TODO change this exception to keyDoesNotExist
        gateway_proxy.get_public_authenticator(keystore_uid=parameters["keystore_uid"])

    gateway_proxy.set_public_authenticator(keystore_uid=parameters["keystore_uid"],
                                           keystore_owner=parameters["keystore_owner"],
                                           keystore_secret=parameters["keystore_secret"],
                                           public_keys=parameters["public_keys"])

    public_authenticator = gateway_proxy.get_public_authenticator(keystore_uid=parameters["keystore_uid"])

    symkeys_data_to_decrypt = []

    for public_key in public_authenticator["public_keys"]:
        symkeys_data_to_decrypt.append(
            dict(
                cryptainer_uid=generate_uuid0(),
                cryptainer_metadata={},
                symkey_ciphertext=public_key["key_value"],
                keychain_uid=public_key["keychain_uid"],
                key_algo=public_key["key_algo"],
            )
        )

    decryption_request_parameter = {
        "keystore_uid": parameters["keystore_uid"],
        "requester_uid": generate_uuid0(),
        "description": "Bien vouloir nous aider pour le dechiffrement de cette clé.",
        "response_public_key": get_random_bytes(20),
        "symkeys_data_to_decrypt": symkeys_data_to_decrypt
    }

    # Soumettre une demande de déchiffrement
    submit_decryption_request(keystore_uid=decryption_request_parameter["keystore_uid"],
                              requester_uid=decryption_request_parameter["requester_uid"],
                              description=decryption_request_parameter["description"],
                              response_public_key=decryption_request_parameter["response_public_key"],
                              symkeys_data_to_decrypt=decryption_request_parameter["symkeys_data_to_decrypt"])

    # Soumettre une 2e demande de déchiffrement
    submit_decryption_request(keystore_uid=decryption_request_parameter["keystore_uid"],
                              requester_uid=decryption_request_parameter["requester_uid"],
                              description=decryption_request_parameter["description"],
                              response_public_key=decryption_request_parameter["response_public_key"],
                              symkeys_data_to_decrypt=decryption_request_parameter["symkeys_data_to_decrypt"])

    # Liste des demandes de déchiffrement par le nvr
    wadevice_decryption_requests = list_wadevice_decryption_requests(
        requester_uid=decryption_request_parameter["requester_uid"])

    # Liste des demandes de déchiffrement par le nvr avec un requester_uid inexistant

    with pytest.raises(ExistenceError):
        list_wadevice_decryption_requests(requester_uid=generate_uuid0())


    # print(">>>>>>>>>>>>>>>>>>>>>>>>>>", wadevice_decryption_requests)

    assert wadevice_decryption_requests[0]["requester_uid"] == decryption_request_parameter["requester_uid"]
    assert wadevice_decryption_requests[0]["response_public_key"] == decryption_request_parameter["response_public_key"]
    assert wadevice_decryption_requests[0]["request_status"] == RequestStatus.PENDING
    assert wadevice_decryption_requests[0]["symkeys_decryption"] == [{
        'cryptainer_uid': symkeys_data_to_decrypt[0]["cryptainer_uid"],
        'cryptainer_metadata': symkeys_data_to_decrypt[0]["cryptainer_metadata"],
        'request_data': symkeys_data_to_decrypt[0]["symkey_ciphertext"],
        'response_data': b'',
        'decryption_status': DecryptionStatus.PENDING
    }, {
        'cryptainer_uid': symkeys_data_to_decrypt[1]["cryptainer_uid"],
        'cryptainer_metadata': symkeys_data_to_decrypt[1]["cryptainer_metadata"],
        'request_data': symkeys_data_to_decrypt[1]["symkey_ciphertext"],
        'response_data': b'',
        'decryption_status': DecryptionStatus.PENDING
    }]

    # Authentifieur n'existe pas dans le dépôt distant
    corrupted_decryption_request_parameter1 = decryption_request_parameter.copy()
    corrupted_decryption_request_parameter1["keystore_uid"] = generate_uuid0()
    with pytest.raises(KeystoreDoesNotExist):
        submit_decryption_request(keystore_uid=corrupted_decryption_request_parameter1["keystore_uid"],
                                  requester_uid=corrupted_decryption_request_parameter1["requester_uid"],
                                  description=corrupted_decryption_request_parameter1["description"],
                                  response_public_key=corrupted_decryption_request_parameter1["response_public_key"],
                                  symkeys_data_to_decrypt=corrupted_decryption_request_parameter1[
                                      "symkeys_data_to_decrypt"])

    # Les données entrées ne sont pas correctes(erreur de lors de la validation de schema)
    corrupted_decryption_request_parameter2 = decryption_request_parameter.copy()
    corrupted_decryption_request_parameter2["symkeys_data_to_decrypt"][0]["key_algo"] = "AES_AES"

    with pytest.raises(SchemaValidationError):
        submit_decryption_request(keystore_uid=corrupted_decryption_request_parameter2["keystore_uid"],
                                  requester_uid=corrupted_decryption_request_parameter2["requester_uid"],
                                  description=corrupted_decryption_request_parameter2["description"],
                                  response_public_key=corrupted_decryption_request_parameter2["response_public_key"],
                                  symkeys_data_to_decrypt=corrupted_decryption_request_parameter2[
                                      "symkeys_data_to_decrypt"])

    # La clé n'existe pas dans le keystore du public authenticator
    corrupted_decryption_request_parameter3 = decryption_request_parameter.copy()
    corrupted_decryption_request_parameter3["symkeys_data_to_decrypt"][0]["key_algo"] = "RSA_OAEP"
    corrupted_decryption_request_parameter3["symkeys_data_to_decrypt"][0]["keychain_uid"] = generate_uuid0()
    with pytest.raises(KeyDoesNotExist):
        submit_decryption_request(keystore_uid=corrupted_decryption_request_parameter3["keystore_uid"],
                                  requester_uid=corrupted_decryption_request_parameter3["requester_uid"],
                                  description=corrupted_decryption_request_parameter3["description"],
                                  response_public_key=corrupted_decryption_request_parameter3["response_public_key"],
                                  symkeys_data_to_decrypt=corrupted_decryption_request_parameter3[
                                      "symkeys_data_to_decrypt"])

    # Rejecter une demande de déchiffrement
    reject_decryption_request(wadevice_decryption_requests[0]["decryption_request_uid"])

    # Rejecter une demande de déchiffrement qui n'existe pas
    with pytest.raises(ExistenceError):
        reject_decryption_request(decryption_request_uid=generate_uuid0())

    #  Liste des demandes de déchiffrement par authentifieur
    authenticator_decryption_requests = list_authenticator_decryption_requests(
        keystore_uid=decryption_request_parameter["keystore_uid"])

    #  Liste des demandes de déchiffrement par authentifieur avec keystore qui n'existe pas
    with pytest.raises(ExistenceError):
        list_authenticator_decryption_requests(keystore_uid=generate_uuid0())

    assert authenticator_decryption_requests[0]["request_status"] == RequestStatus.REJECTED
    assert authenticator_decryption_requests[1]["request_status"] == RequestStatus.PENDING

    symkeys_decryption_result = [{
        "keychain_uid": parameters["public_keys"][0]["keychain_uid"],
        "key_algo":parameters["public_keys"][0]["key_algo"],
        "response_data": b'\xdd\xfa\xc8\xe9K-}[\xc1W\\\xd9{l\xb2\x1a\xfb\xc4\xa9\xb8',
        "decryption_status": DecryptionStatus.DECRYPTED
    },
        {
            "keychain_uid": parameters["public_keys"][1]["keychain_uid"],
            "key_algo": parameters["public_keys"][1]["key_algo"],
            "response_data": b'\xdd\xfa\xc8\xe9K-}[\xc1W\\\xd9{l\xb2\x1a\xfb\xc4\xa9\xb7',
            "decryption_status": DecryptionStatus.DECRYPTED
        }
    ]
    # Accepter la prémiere demande de dechiffrement
    accept_decryption_request(authenticator_decryption_requests[0]["decryption_request_uid"], symkeys_decryption_result)


    authenticator_decryption_requests = list_authenticator_decryption_requests(
        keystore_uid=decryption_request_parameter["keystore_uid"])

    assert authenticator_decryption_requests[0]["request_status"] == RequestStatus.ACCEPTED
    assert authenticator_decryption_requests[0]["symkeys_decryption"] == [{
        'cryptainer_uid': symkeys_data_to_decrypt[0]["cryptainer_uid"],
        'cryptainer_metadata': symkeys_data_to_decrypt[0]["cryptainer_metadata"],
        'request_data': symkeys_data_to_decrypt[0]["symkey_ciphertext"],
        'response_data': b'\xdd\xfa\xc8\xe9K-}[\xc1W\\\xd9{l\xb2\x1a\xfb\xc4\xa9\xb8',
        'decryption_status': DecryptionStatus.DECRYPTED
    }, {
        'cryptainer_uid': symkeys_data_to_decrypt[1]["cryptainer_uid"],
        'cryptainer_metadata': symkeys_data_to_decrypt[1]["cryptainer_metadata"],
        'request_data': symkeys_data_to_decrypt[1]["symkey_ciphertext"],
        'response_data': b'\xdd\xfa\xc8\xe9K-}[\xc1W\\\xd9{l\xb2\x1a\xfb\xc4\xa9\xb7',
        'decryption_status': DecryptionStatus.DECRYPTED
    }]

    # Accepter la prémiere demande de dechiffrement avec un resultat incohérent

    symkeys_decryption_result = [{
        "keychain_uid": parameters["public_keys"][1]["keychain_uid"],
        "key_algo": parameters["public_keys"][1]["key_algo"],
        "response_data": b'\xdd\xfa\xc8\xe9K-}[\xc1W\\\xd9{l\xb2\x1a\xfb\xc4\xa9\xb7',
        "decryption_status": DecryptionStatus.DECRYPTED
    }]

    with pytest.raises(ExistenceError):
        accept_decryption_request(authenticator_decryption_requests[1]["decryption_request_uid"], symkeys_decryption_result)




