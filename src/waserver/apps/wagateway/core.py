import uuid

from django.db import transaction

from schema import And, Or, Optional, Schema, SchemaError
from wacryptolib.cipher import SUPPORTED_CIPHER_ALGOS
from wacryptolib.exceptions import SchemaValidationError, KeystoreAlreadyExists, KeystoreDoesNotExist, ValidationError, \
    KeyDoesNotExist, ExistenceError
from wacryptolib.utilities import get_validation_micro_schemas
from waserver.apps.wagateway.models import PublicAuthenticator, AuthenticatorPublicKey, DecryptionRequest, \
    SymkeyDecryption, RequestStatus, DecryptionStatus

from waserver.apps.wagateway.serializers import PublicAuthenticatorSerializer, DecryptionRequestSerializer, \
    AuthenticatorPublicKeySerializer


# FIXME WEIRD NAME
class PermissionAuthenticatorError(ExistenceError):  # TODO Put this in wacryptolib
    pass


class AuthenticatorDoesNotExist(ExistenceError):  # TODO Put this in wacryptolib
    pass


def get_public_authenticator(keystore_uid, keystore_secret=None):
    try:
        authenticator_user = PublicAuthenticator.objects.get(keystore_uid=keystore_uid)
        if keystore_secret:
            if keystore_secret != authenticator_user.keystore_secret:
                raise PermissionAuthenticatorError("Wrong authenticator secret")  # FIXME raise better permission error OK
        return PublicAuthenticatorSerializer(authenticator_user).data
    except PublicAuthenticator.DoesNotExist:
        raise AuthenticatorDoesNotExist("Authenticator User does not exist")  # TODO change this exception error OK


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
                AuthenticatorPublicKey.objects.create(authenticator_user=public_authenticator,
                                                      keychain_uid=public_key["keychain_uid"],
                                                      key_algo=public_key["key_algo"],
                                                      key_value=public_key["key_value"])


def submit_decryption_request(authenticator_keystore_uid: uuid.UUID, requester_uid: uuid.UUID, description: str,
                              response_public_key: bytes, response_keychain_uid: uuid.UUID, response_key_algo: str,
                              symkeys_data_to_decrypt: list):
    # TODO Traiter le cas où les request_data des symkeys doivent être uniques pour une même demande de dechiffrement
    with transaction.atomic():

        decryption_request_tree = {
            "keystore_uid": authenticator_keystore_uid,
            "requester_uid": requester_uid,
            "description": description,
            "response_public_key": response_public_key,
            "response_keychain_uid": response_keychain_uid,
            "response_key_algo": response_key_algo,
            "symkeys_data_to_decrypt": symkeys_data_to_decrypt
        }

        validate_data_tree_with_pythonschema(data_tree=decryption_request_tree,
                                             valid_schema=SCHEMA_OF_DECRYTION_REQUEST_INPUT_PARAMETERS)

        try:
            public_authenticator = PublicAuthenticator.objects.get(keystore_uid=authenticator_keystore_uid)
            # FIXME use .get() because UNICITY OK
        except PublicAuthenticator.DoesNotExist:
            raise AuthenticatorDoesNotExist("Authenticator %s does not exists in sql storage" % authenticator_keystore_uid)
            # TODO Create and Change this this exception to AuthenticatorDoesNotEXIST OK

        decryption_request = DecryptionRequest.objects.create(public_authenticator=public_authenticator,
                                                              requester_uid=requester_uid,
                                                              description=description,
                                                              response_public_key=response_public_key,
                                                              response_keychain_uid=response_keychain_uid,
                                                              response_key_algo=response_key_algo)

        for symkey_data_to_decrypt in symkeys_data_to_decrypt:
            # TODO vérifier que la clé à déchiffrer est présent dans authenticator_public_keys OK
            try:
                authenticator_public_key = public_authenticator.public_keys.get(
                    keychain_uid=symkey_data_to_decrypt['keychain_uid'], key_algo=symkey_data_to_decrypt['key_algo'])
            except AuthenticatorPublicKey.DoesNotExist:
                raise KeyDoesNotExist(
                    "Public key %s does not exists in key storage in %s authenticator" % (
                    symkey_data_to_decrypt['keychain_uid'], authenticator_keystore_uid))

            SymkeyDecryption.objects.create(decryption_request=decryption_request,
                                            cryptainer_uid=symkey_data_to_decrypt["cryptainer_uid"],
                                            cryptainer_metadata=symkey_data_to_decrypt["cryptainer_metadata"],
                                            authenticator_public_key=authenticator_public_key,
                                            request_data=symkey_data_to_decrypt["symkey_ciphertext"])


def list_wadevice_decryption_requests(requester_uid: uuid.UUID):
    decryption_request_by_requester_uid = DecryptionRequest.objects.filter(requester_uid=requester_uid)
    if not decryption_request_by_requester_uid.exists():
        raise ExistenceError(
            "Requester uid %s does not have a decryption requests" % requester_uid)  # TODO Change this exception
    return DecryptionRequestSerializer(decryption_request_by_requester_uid, many=True).data


def list_authenticator_decryption_requests(authenticator_keystore_uid: uuid.UUID, authenticator_keystore_secret: str):
    # FIXMe rename to authenticator_keystore_uid and authenticator_keystore_secret?  OK

    # Appelé par authentifieur, authentifié via keystore_secret  # FIXME english comments only
    decryption_requests_for_keystore_uid = DecryptionRequest.objects.filter(
        public_authenticator__keystore_uid=authenticator_keystore_uid)
    # TODO Rename -> decryption_requests_for_keystore_uid OK

    if not decryption_requests_for_keystore_uid.exists():  # FIXME wrong, it must be e.g. xxx.count()
        raise ExistenceError(
            "No decryption request concerns %s authenticator" % authenticator_keystore_uid)  # TODO Change this exception

    # FIXME do that permission check FIRST, before any other work
    try:
        public_authenticator = PublicAuthenticator.objects.get(keystore_uid=authenticator_keystore_uid)
        # FIXME use .get() because UNICITY OK
    except PublicAuthenticator.DoesNotExist:
        raise AuthenticatorDoesNotExist("Authenticator User does not exist")
    password_is_correct = public_authenticator.check_keystore_secret(authenticator_keystore_secret)
    if not password_is_correct:
        raise PermissionAuthenticatorError("The provided keystore secret is not correct for target authenticator")

    return DecryptionRequestSerializer(decryption_requests_for_keystore_uid, many=True).data


def reject_decryption_request(authenticator_keystore_secret: str,
                              decryption_request_uid: uuid.UUID):  # Appelé par authentifieur, authentifié via keystore_secret

    decryption_request = DecryptionRequest.objects.get(decryption_request_uid=decryption_request_uid)

    if not decryption_request:
        raise ExistenceError(
            "Decryption request %s does not exist" % decryption_request_uid)  # TODO Change this exception

    # FIXME DUPLICATED CODE - not ok, factorize that with above
    public_authenticator = decryption_request.public_authenticator
    password_is_correct = public_authenticator.check_keystore_secret(authenticator_keystore_secret)
    if not password_is_correct:
        raise PermissionAuthenticatorError("The keystore secret of authenticator is not correct")

    decryption_request.request_status = RequestStatus.REJECTED
    decryption_request.save()


def accept_decryption_request(authenticator_keystore_secret: str, decryption_request_uid,
                              symkey_decryption_results: list):  # Appelé par authentifieur, authentifié via keystore_secret  # FIXME english

    symkey_decryptions = SymkeyDecryption.objects.filter(
        decryption_request__decryption_request_uid=decryption_request_uid)

    if not symkey_decryptions:
        raise ExistenceError("Decryption request %s does not exist", decryption_request_uid)

    # FIXME DUPLICATED CODE - not ok, factorize that with above TOO
    public_authenticator = symkey_decryptions[0].decryption_request.public_authenticator
    password_is_correct = public_authenticator.check_keystore_secret(authenticator_keystore_secret)
    if not password_is_correct:
        raise PermissionAuthenticatorError("The keystore secret of authenticator is not correct")

    expected_request_data = set()

    for symkey_decryption in symkey_decryptions:
        request_data = symkey_decryption.request_data
        expected_request_data.add(request_data)

    received_request_data = set(
        symkey_decryption_result["request_data"] for symkey_decryption_result in symkey_decryption_results)

    exceeding_request_data_among_received = received_request_data - expected_request_data
    missing_request_data_among_received = expected_request_data - received_request_data

    if exceeding_request_data_among_received or missing_request_data_among_received:
        raise ExistenceError("Difference between expected and received request data, %s does not exist in expected "
                             "request data and %s is expected but not received ",
                             exceeding_request_data_among_received,
                             missing_request_data_among_received)

    for symkey_decryption in symkey_decryptions:

        for symkey_decryption_result in symkey_decryption_results:

            if symkey_decryption.request_data == symkey_decryption_result["request_data"]:
                symkey_decryption.response_data = symkey_decryption_result["response_data"]
                symkey_decryption.decryption_status = symkey_decryption_result["decryption_status"]
                symkey_decryption.save()

    DecryptionRequest.objects.filter(decryption_request_uid=decryption_request_uid).update(
        request_status=RequestStatus.ACCEPTED)


micro_schema = get_validation_micro_schemas(extended_json_format=False)

SCHEMA_OF_DECRYTION_REQUEST_INPUT_PARAMETERS = Schema({
    "keystore_uid": micro_schema.schema_uid,
    "requester_uid": micro_schema.schema_uid,
    "description": And(str, len),
    "response_public_key": micro_schema.schema_binary,
    "response_keychain_uid": micro_schema.schema_uid,
    "response_key_algo": Or(*SUPPORTED_CIPHER_ALGOS),
    "symkeys_data_to_decrypt": [{
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
