import copy
import pytest
import random
import requests
from Crypto.Random import get_random_bytes

from wacryptolib.exceptions import KeystoreAlreadyExists, ExistenceError, \
    SchemaValidationError, ValidationError, KeyDoesNotExist
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.keygen import generate_symkey, generate_keypair
from wacryptolib.utilities import generate_uuid0
from waserver.apps.wagateway.core import validate_data_tree_with_pythonschema, PUBLIC_AUTHENTICATOR_SCHEMA, \
    AuthenticationError, AuthenticatorDoesNotExist
from waserver.apps.wagateway.models import PublicAuthenticator, RevelationRequestStatus, SymkeyDecryptionStatus
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
        keystore_owner="keystore_owner" + str(random.randint(1, 9)),
        keystore_secret="my_keystore_secret",
        keystore_uid=generate_uuid0(),
        public_keys=public_keys
    )
    return parameters


def test_jsonrpc_set_and_get_public_authenticator_validation_errors(live_server):
    jsonrpc_url = live_server.url + "/gateway/jsonrpc/"

    gateway_proxy = JsonRpcProxy(
        url=jsonrpc_url, response_error_handler=status_slugs_response_error_handler
    )

    with pytest.raises(ValidationError, match="keyword arguments"):
        gateway_proxy.get_public_authenticator(generate_uuid0())  # SPECIAL - Passing parameters by position is forbidden

    with pytest.raises(ValidationError):
        gateway_proxy.get_public_authenticator()  # Missing arguments

    with pytest.raises(ValidationError):
        gateway_proxy.get_public_authenticator(keystore_uid="bad-uid")

    with pytest.raises(ValidationError):
        gateway_proxy.get_public_authenticator(keystore_uid=generate_uuid0(), weird_arg=22)  # Unexpected argument

    # ---

    with pytest.raises(ValidationError):
        gateway_proxy.set_public_authenticator()   # Missing arguments

    with pytest.raises(ValidationError):
        gateway_proxy.set_public_authenticator(keystore_uid=generate_uuid0(),
                                               keystore_owner="Some Owner",
                                               keystore_secret="whatever",
                                               public_keys=[{}])  # Key format is incorrect

    with pytest.raises(ValidationError):
        gateway_proxy.set_public_authenticator(keystore_uid=generate_uuid0(),
                                               keystore_owner="Some Owner",
                                               keystore_secret="whatever",
                                               weird_argument=3333)  # Unexpected argument


def test_jsonrpc_set_and_get_public_authenticator_workflow(live_server):
    jsonrpc_url = live_server.url + "/gateway/jsonrpc/"

    gateway_proxy = JsonRpcProxy(
        url=jsonrpc_url, response_error_handler=status_slugs_response_error_handler
    )

    parameters = _generate_authenticator_parameter_tree(2)

    with pytest.raises(AuthenticatorDoesNotExist):
        gateway_proxy.get_public_authenticator(keystore_uid=parameters["keystore_uid"])

    gateway_proxy.set_public_authenticator(**parameters)

    with pytest.raises(KeystoreAlreadyExists):
        gateway_proxy.set_public_authenticator(**parameters)

    with pytest.raises(SchemaValidationError):
        gateway_proxy.set_public_authenticator(keystore_uid=parameters["keystore_uid"],
                                               keystore_owner=parameters["keystore_owner"],
                                               keystore_secret="whatever",
                                               public_keys=[])  # Important, EMPTY keys are not allowed

    with pytest.raises(SchemaValidationError):
        gateway_proxy.set_public_authenticator(keystore_uid="hello-bad-uid",
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

    with pytest.raises(AuthenticationError):
        gateway_proxy.get_public_authenticator(keystore_uid=parameters["keystore_uid"], keystore_secret="wrongvalue")

    # Authentication if keystore_secret is given
    public_authenticator1 = gateway_proxy.get_public_authenticator(keystore_uid=parameters["keystore_uid"],
                                                                   keystore_secret="my_keystore_secret")

    # No authentication if no keystore_secret is given
    public_authenticator2 = gateway_proxy.get_public_authenticator(keystore_uid=parameters["keystore_uid"])

    expected_authenticator_dict = parameters.copy()
    del expected_authenticator_dict["keystore_secret"]

    assert public_authenticator1 == expected_authenticator_dict
    assert public_authenticator2 == expected_authenticator_dict

    validate_data_tree_with_pythonschema(public_authenticator1, PUBLIC_AUTHENTICATOR_SCHEMA)


def __NOPE_DISABLED_NOW_test_rest_api_get_public_authenticator(live_server):
    parameters = _generate_authenticator_parameter_tree(2, key_value="aé$£é&ö".encode("utf8"))

    set_public_authenticator_view(None,
                                  **parameters)

    url = live_server.url + "/gateway/rest/public-authenticators/"
    response = requests.get(url)
    assert response.status_code == 200
    public_authenticators = response.json()
    assert len(public_authenticators) == 1
    public_authenticator = public_authenticators[0]
    # from pprint import pprint
    # pprint(public_authenticator)

    # FIXME later add a new pythonschema for this "raw json" format?
    assert public_authenticator == {'keystore_owner': parameters["keystore_owner"],
                                    'keystore_uid': str(parameters["keystore_uid"]),
                                    # Uses standard string representation of UUIDs
                                    'public_keys': [{'key_algo': 'RSA_OAEP',
                                                     'keychain_uid': str(parameters["public_keys"][0]["keychain_uid"]),
                                                     'key_value': 'YcOpJMKjw6kmw7Y='},
                                                    # Direct base64 is used instead of $binary dict
                                                    {'key_algo': 'RSA_OAEP',
                                                     'keychain_uid': str(parameters["public_keys"][1]["keychain_uid"]),
                                                     'key_value': 'YcOpJMKjw6kmw7Y='}]}


def test_revelation_request_validation_errors(live_server):
    jsonrpc_url = live_server.url + "/gateway/jsonrpc/"

    gateway_proxy = JsonRpcProxy(
        url=jsonrpc_url, response_error_handler=status_slugs_response_error_handler
    )

    with pytest.raises(ValidationError):
        gateway_proxy.list_requestor_revelation_requests()

    with pytest.raises(ValidationError):
        gateway_proxy.list_requestor_revelation_requests(
            revelation_requestor_uid="bad-uid-really",
        )

    with pytest.raises(ValidationError):
        gateway_proxy.list_requestor_revelation_requests(
            revelation_requestor_uid=generate_uuid0(),
            weird_argument=-29236
        )

    # ---

    with pytest.raises(ValidationError):
        gateway_proxy.list_authenticator_revelation_requests()

    with pytest.raises(ValidationError):
        gateway_proxy.list_authenticator_revelation_requests(
            authenticator_keystore_uid="bad-uid-really",
            authenticator_keystore_secret="ssqsqsd",
        )

    with pytest.raises(ValidationError):
        gateway_proxy.list_authenticator_revelation_requests(
            authenticator_keystore_uid=generate_uuid0(),
            authenticator_keystore_secret="some secret key",
            weird_argument=27252827
        )

    # ---

    with pytest.raises(ValidationError):
        gateway_proxy.submit_revelation_request()

    with pytest.raises(ValidationError):
        gateway_proxy.submit_revelation_request(
            authenticator_keystore_uid="bad uid",
            revelation_requestor_uid=generate_uuid0(),
            revelation_request_description="some description",
            revelation_response_public_key=b"sdsds",
            revelation_response_keychain_uid=generate_uuid0(),
            revelation_response_key_algo="RSA_OAEP",
            symkey_decryption_requests=[],
        )

    with pytest.raises(ValidationError):
        gateway_proxy.submit_revelation_request(
            authenticator_keystore_uid=generate_uuid0(),
            weird_argument=27252827)

    # ---

    with pytest.raises(ValidationError):
        gateway_proxy.reject_revelation_request()

    with pytest.raises(ValidationError):
        gateway_proxy.reject_revelation_request(
            revelation_request_uid="bad uid",
            authenticator_keystore_secret="some str",
        )

    with pytest.raises(ValidationError):
        gateway_proxy.reject_revelation_request(
            revelation_request_uid=generate_uuid0(),
            authenticator_keystore_secret="some str again",
            weird_argument=27252827)

    # ---

    with pytest.raises(ValidationError):
        gateway_proxy.reject_revelation_request()

    with pytest.raises(ValidationError):
        gateway_proxy.reject_revelation_request(
            revelation_request_uid="bad uid",
            authenticator_keystore_secret="some str",
        )

    with pytest.raises(ValidationError):
        gateway_proxy.reject_revelation_request(
            revelation_request_uid=generate_uuid0(),
            authenticator_keystore_secret="some str again",
            weird_argument=27252827)

    # ---

    with pytest.raises(ValidationError):
        gateway_proxy.accept_revelation_request()

    with pytest.raises(ValidationError):
        gateway_proxy.accept_revelation_request(
            revelation_request_uid=generate_uuid0(),
            authenticator_keystore_secret="some str secret",
            symkey_decryption_results=[],
        )

    with pytest.raises(ValidationError):
        gateway_proxy.accept_revelation_request(
            revelation_request_uid=generate_uuid0(),
            authenticator_keystore_secret="some str secret",
            symkey_decryption_results=[dict(symkey_decryption_request_data=b"ssasd",
                                            symkey_decryption_response_data=b"azeze",
                                            symkey_decryption_status="UNEXISTING-STATUS")],
        )

    with pytest.raises(ValidationError):
        gateway_proxy.accept_revelation_request(
            revelation_request_uid=generate_uuid0(),
            authenticator_keystore_secret="some str secret",
            weird_argument=1156252
        )


def test_revelation_request_workflow(live_server):
    jsonrpc_url = live_server.url + "/gateway/jsonrpc/"

    gateway_proxy = JsonRpcProxy(
        url=jsonrpc_url, response_error_handler=status_slugs_response_error_handler
    )

    parameters1 = _generate_authenticator_parameter_tree(2)
    parameters2 = _generate_authenticator_parameter_tree(2)

    key_algo = "RSA_OAEP"

    # Check that the public authenticator does not exist on the server
    with pytest.raises(AuthenticatorDoesNotExist):
        gateway_proxy.get_public_authenticator(keystore_uid=parameters1["keystore_uid"])

    with pytest.raises(AuthenticatorDoesNotExist):
        gateway_proxy.get_public_authenticator(keystore_uid=parameters2["keystore_uid"])

    # Publish the two authenticators on the server
    gateway_proxy.set_public_authenticator(**parameters1)
    gateway_proxy.set_public_authenticator(**parameters2)

    revelation_requests = gateway_proxy.list_authenticator_revelation_requests(
        authenticator_keystore_uid=parameters1["keystore_uid"],
        authenticator_keystore_secret=parameters1["keystore_secret"])
    assert revelation_requests == []

    # Retrieve in a list all the public authenticators
    public_authenticators = []
    public_authenticator1 = gateway_proxy.get_public_authenticator(keystore_uid=parameters1["keystore_uid"])
    public_authenticator2 = gateway_proxy.get_public_authenticator(keystore_uid=parameters2["keystore_uid"])
    public_authenticators.append(public_authenticator1)
    public_authenticators.append(public_authenticator2)

    # Create keypair used by remote server to answer safely
    response_keypair = generate_keypair(key_algo=key_algo)

    # Create symkey decryption
    symkey_dict = generate_symkey(cipher_algo="AES_CBC")

    revelation_request_parameters = []

    for public_authenticator in public_authenticators:
        revelation_request_parameters = {
            "authenticator_keystore_uid": public_authenticator["keystore_uid"],
            "revelation_requestor_uid": generate_uuid0(),
            "revelation_request_description": "Merci de bien vouloir nous aider pour le déchiffrement de cette clé.",
            "revelation_response_public_key": response_keypair["public_key"],
            "revelation_response_keychain_uid": generate_uuid0(),
            "revelation_response_key_algo": key_algo,
            "symkey_decryption_requests": [{
                "cryptainer_uid": generate_uuid0(),
                "cryptainer_metadata": {},
                "symkey_ciphertext": symkey_dict["key"],
                "keychain_uid": public_authenticator["public_keys"][0]["keychain_uid"],
                "key_algo": public_authenticator["public_keys"][0]["key_algo"],
            }]
        }

        # Submit revelation_request
        gateway_proxy.submit_revelation_request(**revelation_request_parameters)

        revelation_request_parameters_broken = copy.deepcopy(revelation_request_parameters)
        revelation_request_parameters_broken["symkey_decryption_requests"].append({
            "cryptainer_uid": generate_uuid0(),
            "cryptainer_metadata": {},
            "symkey_ciphertext": symkey_dict["key"],
            "keychain_uid": generate_uuid0(),  # WRONG VALUE
            "key_algo": public_authenticator["public_keys"][0]["key_algo"],
        })
        with pytest.raises(KeyDoesNotExist):  # Target public authenticator key not found
            gateway_proxy.submit_revelation_request(**revelation_request_parameters_broken)

        revelation_request_parameters.append(revelation_request_parameters)

    # List of decryption requests for the first authenticator
    revelation_requests_by_keystore_uid = gateway_proxy.list_authenticator_revelation_requests(
        authenticator_keystore_uid=revelation_request_parameters[0]["authenticator_keystore_uid"],
        authenticator_keystore_secret="keystore_secret")

    assert len(revelation_requests_by_keystore_uid) == 1
    revelation_request = revelation_requests_by_keystore_uid[0]

    # FIXME DRY this code regarding revelation_request_parameters[0] etc., using dict comprehensions and equality comparisons if possible

    assert revelation_request["revelation_requestor_uid"] == revelation_request_parameters[0]["revelation_requestor_uid"]
    assert revelation_request["revelation_response_public_key"] == revelation_request_parameters[0][
        "revelation_response_public_key"]
    assert revelation_request["revelation_response_keychain_uid"] == revelation_request_parameters[0][
        "revelation_response_keychain_uid"]
    assert revelation_request["revelation_response_key_algo"] == revelation_request_parameters[0][
        "revelation_response_key_algo"]
    assert revelation_request["revelation_request_status"] == RevelationRequestStatus.PENDING

    assert len(revelation_request["symkey_decryption_requests"]) == 1
    symkey_decryption_request = revelation_request["symkey_decryption_requests"][0]

    assert symkey_decryption_request["symkey_decryption_status"] == SymkeyDecryptionStatus.PENDING

    assert symkey_decryption_request["target_public_authenticator_key"][
               "keychain_uid"] == \
           revelation_request_parameters[0]["symkey_decryption_requests"][0]["keychain_uid"]
    assert symkey_decryption_request["target_public_authenticator_key"][
               "key_algo"] == \
           revelation_request_parameters[0]["symkey_decryption_requests"][0]["key_algo"]

    # List of decryption requests for the authenticator with keystore ou keystore_secret that does not exist
    with pytest.raises(AuthenticatorDoesNotExist):
        gateway_proxy.list_authenticator_revelation_requests(authenticator_keystore_uid=generate_uuid0(),
                                               authenticator_keystore_secret="keystore_secret")

    with pytest.raises(AuthenticationError):
        gateway_proxy.list_authenticator_revelation_requests(
            authenticator_keystore_uid=revelation_request_parameters[0]["authenticator_keystore_uid"],
            authenticator_keystore_secret="toto")

    # List of decryption requests by NVR
    revelation_request_for_requestor_uid1 = gateway_proxy.list_requestor_revelation_requests(
        revelation_requestor_uid=revelation_request_parameters[1]["revelation_requestor_uid"])

    # FIXME DRY this code like above, and rename revelation_request_for_requestor_uid1 which must be PLURAL

    assert revelation_request_for_requestor_uid1[0]["revelation_requestor_uid"] == revelation_request_parameters[1]["revelation_requestor_uid"]
    assert revelation_request_for_requestor_uid1[0]["revelation_response_public_key"] == revelation_request_parameters[1][
        "revelation_response_public_key"]
    assert revelation_request_for_requestor_uid1[0]["revelation_response_keychain_uid"] == revelation_request_parameters[1][
        "revelation_response_keychain_uid"]
    assert revelation_request_for_requestor_uid1[0]["revelation_response_key_algo"] == revelation_request_parameters[1][
        "revelation_response_key_algo"]
    assert revelation_request_for_requestor_uid1[0]["revelation_request_status"] == RevelationRequestStatus.PENDING
    assert revelation_request_for_requestor_uid1[0]["symkey_decryption_requests"][0][
               "symkey_decryption_status"] == SymkeyDecryptionStatus.PENDING
    assert revelation_request_for_requestor_uid1[0]["symkey_decryption_requests"][0]["target_public_authenticator_key"][
               "keychain_uid"] == revelation_request_parameters[1]["symkey_decryption_requests"][0]["keychain_uid"]
    assert revelation_request_for_requestor_uid1[0]["symkey_decryption_requests"][0]["target_public_authenticator_key"]["key_algo"] == \
           revelation_request_parameters[1]["symkey_decryption_requests"][0]["key_algo"]

    assert gateway_proxy.list_requestor_revelation_requests(revelation_requestor_uid=generate_uuid0()) == []  # No error on unknown revelation_requestor_uid

    # Reject a decryption request for requester1
    gateway_proxy.reject_revelation_request(authenticator_keystore_secret="keystore_secret",
                              revelation_request_uid=revelation_request_for_requestor_uid1[0]["revelation_request_uid"])

    revelation_request_for_requestor_uid1 = gateway_proxy.list_requestor_revelation_requests(  # FIXME NAMING - must be PLURAL
        revelation_requestor_uid=revelation_request_parameters[1]["revelation_requestor_uid"])
    assert revelation_request_for_requestor_uid1[0]["revelation_request_status"] == RevelationRequestStatus.REJECTED
    assert revelation_request_for_requestor_uid1[0]["symkey_decryption_requests"][0][
               "symkey_decryption_status"] == SymkeyDecryptionStatus.PENDING
    assert revelation_request_for_requestor_uid1[0]["symkey_decryption_requests"][0]["symkey_decryption_response_data"] == b""

    # Reject a revelation request that does not exist
    with pytest.raises(ExistenceError):
        gateway_proxy.reject_revelation_request(authenticator_keystore_secret="keystore_secret",
                                  revelation_request_uid=generate_uuid0())

    #  Reject a revelation request with keystore secret unrecognized
    with pytest.raises(AuthenticationError):
        gateway_proxy.reject_revelation_request(
            authenticator_keystore_secret="toto",
            revelation_request_uid=revelation_request_for_requestor_uid1[0]["revelation_request_uid"])

    revelation_request_for_requestor_uid2 = gateway_proxy.list_requestor_revelation_requests(
        revelation_requestor_uid=revelation_request_parameters[1]["revelation_requestor_uid"])

    symkey_decryption_results = [{
        "symkey_decryption_request_data": revelation_request_parameters[1]["symkey_decryption_requests"][0]["symkey_ciphertext"],
        "symkey_decryption_response_data": get_random_bytes(20),
        "symkey_decryption_status": SymkeyDecryptionStatus.DECRYPTED
    }]

    # Accept the second revelation request
    gateway_proxy.accept_revelation_request(authenticator_keystore_secret="keystore_secret",
                              revelation_request_uid=revelation_request_for_requestor_uid2[0]["revelation_request_uid"],
                              symkey_decryption_results=symkey_decryption_results)

    revelation_request_for_requestor_uid2 = gateway_proxy.list_requestor_revelation_requests(
        revelation_requestor_uid=revelation_request_parameters[1]["revelation_requestor_uid"])
    assert revelation_request_for_requestor_uid2[0]["revelation_request_status"] == RevelationRequestStatus.ACCEPTED
    assert revelation_request_for_requestor_uid2[0]["symkey_decryption_requests"][0]["symkey_decryption_status"] == \
           symkey_decryption_results[0]["symkey_decryption_status"]
    assert revelation_request_for_requestor_uid2[0]["symkey_decryption_requests"][0]["symkey_decryption_request_data"] == \
           symkey_decryption_results[0]["symkey_decryption_request_data"]
    assert revelation_request_for_requestor_uid2[0]["symkey_decryption_requests"][0]["symkey_decryption_response_data"] == \
           symkey_decryption_results[0]["symkey_decryption_response_data"]

    # Accept a revelation request that does not exist
    with pytest.raises(ExistenceError):
        gateway_proxy.accept_revelation_request(authenticator_keystore_secret="keystore_secret",
                                  revelation_request_uid=generate_uuid0(),
                                  symkey_decryption_results=symkey_decryption_results)

    # Accept a revelation request having the keystore_secret not matching
    with pytest.raises(AuthenticationError):
        gateway_proxy.accept_revelation_request(
            authenticator_keystore_secret="",
            revelation_request_uid=revelation_request_for_requestor_uid2[0]["revelation_request_uid"],
            symkey_decryption_results=symkey_decryption_results)
