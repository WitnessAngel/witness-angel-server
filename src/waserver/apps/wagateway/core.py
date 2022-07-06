import uuid

from django.db import transaction

from schema import And, Or, Optional, Schema, SchemaError
from wacryptolib.cipher import SUPPORTED_CIPHER_ALGOS
from wacryptolib.exceptions import SchemaValidationError, KeystoreAlreadyExists, KeyDoesNotExist, ExistenceError, \
    AuthenticationError, AuthenticatorDoesNotExist
from wacryptolib.utilities import get_validation_micro_schemas
from waserver.apps.wagateway.models import PublicAuthenticator, PublicAuthenticatorKey, RevelationRequest, \
    SymkeyDecryptionRequest, RevelationRequestStatus

from waserver.apps.wagateway.serializers import PublicAuthenticatorSerializer, RevelationRequestSerializer


def get_public_authenticator(keystore_uid, keystore_secret=None):
    # FIXME validate with tiny SCHEMA, here, too!
    try:
        authenticator_user = PublicAuthenticator.objects.get(keystore_uid=keystore_uid)
        if keystore_secret:  # Optional, only provided to check if owned keystore_secret is still OK
            if keystore_secret != authenticator_user.keystore_secret:
                raise AuthenticationError("Wrong authenticator secret")
        return PublicAuthenticatorSerializer(authenticator_user).data
    except PublicAuthenticator.DoesNotExist:
        raise AuthenticatorDoesNotExist("Authenticator User does not exist") from None


def set_public_authenticator(keystore_owner: str, keystore_secret: str, keystore_uid: uuid.UUID, public_keys: list):
    with transaction.atomic():

        public_authenticator_tree = {
            "keystore_owner": keystore_owner,
            "keystore_secret": keystore_secret,
            "keystore_uid": keystore_uid,
            "public_keys": public_keys
        }

        validate_data_tree_with_pythonschema(data_tree=public_authenticator_tree,
                                             valid_schema=PUBLIC_AUTHENTICATOR_SCHEMA)

        try:
            PublicAuthenticator.objects.get(keystore_uid=keystore_uid)
            raise KeystoreAlreadyExists("Authenticator %s already exists in sql storage" % keystore_uid)
        except PublicAuthenticator.DoesNotExist:
            public_authenticator = PublicAuthenticator(keystore_owner=keystore_owner, keystore_uid=keystore_uid)
            public_authenticator.set_keystore_secret(keystore_secret)
            public_authenticator.save()
            for public_key in public_keys:
                PublicAuthenticatorKey.objects.create(authenticator_user=public_authenticator,
                                                      keychain_uid=public_key["keychain_uid"],
                                                      key_algo=public_key["key_algo"],
                                                      key_value=public_key["key_value"])


def submit_revelation_request(authenticator_keystore_uid: uuid.UUID, revelation_requestor_uid: uuid.UUID,
                              revelation_request_description: str,
                              revelation_response_public_key: bytes, revelation_response_keychain_uid: uuid.UUID,
                              revelation_response_key_algo: str,
                              symkey_decryption_requests: list):
    #  Called by NVR
    # TODO Handle the case where symkey request_data must be unique for the same decryption request
    with transaction.atomic():

        revelation_request_tree = {
            "authenticator_keystore_uid": authenticator_keystore_uid,
            "revelation_requestor_uid": revelation_requestor_uid,
            "revelation_request_description": revelation_request_description,
            "revelation_response_public_key": revelation_response_public_key,
            "revelation_response_keychain_uid": revelation_response_keychain_uid,
            "revelation_response_key_algo": revelation_response_key_algo,
            "symkey_decryption_requests": symkey_decryption_requests
        }

        validate_data_tree_with_pythonschema(data_tree=revelation_request_tree,
                                             valid_schema=REVELATION_REQUEST_INPUT_PARAMETERS_SCHEMA)

        try:
            target_public_authenticator = PublicAuthenticator.objects.get(keystore_uid=authenticator_keystore_uid)

        except PublicAuthenticator.DoesNotExist:
            raise AuthenticatorDoesNotExist(
                "Authenticator %s does not exists in sql storage" % authenticator_keystore_uid)

        revelation_request = RevelationRequest.objects.create(target_public_authenticator=target_public_authenticator,
                                                              revelation_requestor_uid=revelation_requestor_uid,
                                                              revelation_request_description=revelation_request_description,
                                                              revelation_response_public_key=revelation_response_public_key,
                                                              revelation_response_keychain_uid=revelation_response_keychain_uid,
                                                              revelation_response_key_algo=revelation_response_key_algo)

        for symkey_decryption_request in symkey_decryption_requests:

            try:
                target_public_authenticator_key = target_public_authenticator.public_keys.get(
                    keychain_uid=symkey_decryption_request['keychain_uid'],
                    key_algo=symkey_decryption_request['key_algo'])
            except PublicAuthenticatorKey.DoesNotExist:
                raise KeyDoesNotExist(
                    "Public key %s does not exists in key storage in %s authenticator" % (
                        symkey_decryption_request['keychain_uid'], authenticator_keystore_uid))

            SymkeyDecryptionRequest.objects.create(revelation_request=revelation_request,
                                                   cryptainer_uid=symkey_decryption_request["cryptainer_uid"],
                                                   cryptainer_metadata=symkey_decryption_request["cryptainer_metadata"],
                                                   target_public_authenticator_key=target_public_authenticator_key,
                                                   symkey_decryption_request_data=symkey_decryption_request[
                                                       "symkey_ciphertext"])


def list_wadevice_revelation_requests(revelation_requestor_uid: uuid.UUID):
    # Called by NVR
    # FIXME validate params with SCHEMA here
    revelation_request_for_requestor_uid = RevelationRequest.objects.filter(  # FIXME this is PLURAL ("_requests_")
        revelation_requestor_uid=revelation_requestor_uid)
    if not revelation_request_for_requestor_uid.exists():  # FIXME - no exception here, just return empty list
        raise ExistenceError(
            "Requestor uid %s does not have a decryption requests" % revelation_requestor_uid)  # TODO Change this exception
    return RevelationRequestSerializer(revelation_request_for_requestor_uid, many=True).data


def _check_authenticator_authorization(public_authenticator, authenticator_keystore_secret: str):
    password_is_correct = public_authenticator.check_keystore_secret(authenticator_keystore_secret)
    if not password_is_correct:
        raise AuthenticationError("The provided keystore secret is not correct for target authenticator")

    return password_is_correct


def list_authenticator_revelation_requests(authenticator_keystore_uid: uuid.UUID, authenticator_keystore_secret: str):
    # Called by authenticator, authenticated with keystore secret
    # FIXME validate params with tiny SCHEMA here
    try:
        target_public_authenticator = PublicAuthenticator.objects.get(keystore_uid=authenticator_keystore_uid)
        _check_authenticator_authorization(target_public_authenticator, authenticator_keystore_secret)

    except PublicAuthenticator.DoesNotExist:
        raise AuthenticatorDoesNotExist("Authenticator User does not exist")

    revelation_requests_for_keystore_uid = RevelationRequest.objects.filter(
        target_public_authenticator__keystore_uid=authenticator_keystore_uid)

    if not revelation_requests_for_keystore_uid.exists():  # FIXME - no exception here, just return empty list
        raise ExistenceError(
            "No revelation request concerns %s authenticator" % authenticator_keystore_uid)  # TODO Change this exception

    return RevelationRequestSerializer(revelation_requests_for_keystore_uid, many=True).data


def reject_revelation_request(authenticator_keystore_secret: str, revelation_request_uid: uuid.UUID):
    # Called by authenticator, authenticated with keystore secret
    # FIXME validate params with tiny SCHEMA here
    with transaction.atomic():
        try:
            revelation_request = RevelationRequest.objects.get(revelation_request_uid=revelation_request_uid)

            target_public_authenticator = revelation_request.target_public_authenticator

            _check_authenticator_authorization(target_public_authenticator, authenticator_keystore_secret)

        except RevelationRequest.DoesNotExist:
            raise ExistenceError(
                "Decryption request %s does not exist" % revelation_request_uid)  # TODO Change this exception

        revelation_request.revelation_request_status = RevelationRequestStatus.REJECTED
        revelation_request.save()


def accept_revelation_request(authenticator_keystore_secret: str, revelation_request_uid: uuid.UUID,
                              symkey_decryption_results: list):
    #  Called by authenticator, authenticated with keystore secret
    with transaction.atomic():

        try:
            revelation_request = RevelationRequest.objects.get(revelation_request_uid=revelation_request_uid)
            
        except RevelationRequest.DoesNotExist:
            raise ExistenceError(
                "Revelation request %s does not exist" % revelation_request_uid)  # TODO Change this exception

        symkey_decryption_requests = revelation_request.symkey_decryption_requests.all()

        if symkey_decryption_requests.exists():

            target_public_authenticator = symkey_decryption_requests[0].revelation_request.target_public_authenticator

            # Check that authenticator passphrase is correct
            _check_authenticator_authorization(target_public_authenticator, authenticator_keystore_secret)

            expected_request_data = set()

            for symkey_decryption_request in symkey_decryption_requests:
                request_data = symkey_decryption_request.symkey_decryption_request_data
                expected_request_data.add(request_data)

            received_request_data = set(
                symkey_decryption_result["symkey_decryption_request_data"] for symkey_decryption_result in
                symkey_decryption_results)

            exceeding_request_data_among_received = received_request_data - expected_request_data
            missing_request_data_among_received = expected_request_data - received_request_data

            if exceeding_request_data_among_received or missing_request_data_among_received:
                raise ExistenceError("Difference between expected and received request data, %s does not exist in expected "
                                     "request data and %s is expected but not received ",
                                     exceeding_request_data_among_received,
                                     missing_request_data_among_received)

            for symkey_decryption_request in symkey_decryption_requests:

                for symkey_decryption_result in symkey_decryption_results:

                    if symkey_decryption_request.symkey_decryption_request_data == symkey_decryption_result[
                        "symkey_decryption_request_data"]:
                        symkey_decryption_request.symkey_decryption_response_data = symkey_decryption_result[
                            "symkey_decryption_response_data"]
                        symkey_decryption_request.symkey_decryption_status = symkey_decryption_result[
                            "symkey_decryption_status"]
                        symkey_decryption_request.save()

        RevelationRequest.objects.filter(revelation_request_uid=revelation_request_uid).update(
            revelation_request_status=RevelationRequestStatus.ACCEPTED)


micro_schema = get_validation_micro_schemas(extended_json_format=False)

REVELATION_REQUEST_INPUT_PARAMETERS_SCHEMA = Schema({  # FIXME TYPO, and rename XXX_REVELATION_YYY_SCHEMA like below
    "authenticator_keystore_uid": micro_schema.schema_uid,
    "revelation_requestor_uid": micro_schema.schema_uid,
    "revelation_request_description": And(str, len),
    "revelation_response_public_key": micro_schema.schema_binary,
    "revelation_response_keychain_uid": micro_schema.schema_uid,
    "revelation_response_key_algo": Or(*SUPPORTED_CIPHER_ALGOS),
    "symkey_decryption_requests": [{
        "cryptainer_uid": micro_schema.schema_uid,
        "cryptainer_metadata": Or(dict, None),
        "symkey_ciphertext": micro_schema.schema_binary,
        "keychain_uid": micro_schema.schema_uid,
        "key_algo": Or(*SUPPORTED_CIPHER_ALGOS),
    }]
})

PUBLIC_AUTHENTICATOR_SCHEMA = Schema({
    "keystore_owner": And(str, len),
    Optional("keystore_secret"): And(str, len),
    "keystore_uid": micro_schema.schema_uid,
    "public_keys": [
        {
            'keychain_uid': micro_schema.schema_uid,
            'key_algo': Or(*SUPPORTED_CIPHER_ALGOS),
            'key_value': micro_schema.schema_binary
        }
    ]
})


def validate_data_tree_with_pythonschema(data_tree: dict, valid_schema: Schema):  # TODO Add to wacryptolib
    """Allows the validation of a data_tree with a pythonschema

    :param data_tree: data to validate
    :param valid_schema: validation scheme
    """
    # we use the python schema module

    assert isinstance(data_tree, dict), data_tree

    try:
        valid_schema.validate(data_tree)
    except SchemaError as exc:
        raise SchemaValidationError("Error validating data tree with python-schema: {}".format(exc)) from exc
