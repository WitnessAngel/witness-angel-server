import uuid
from datetime import timedelta
from typing import Optional
from uuid import UUID

from django.db import transaction

from schema import And, Or, Schema, SchemaError
from wacryptolib.cipher import SUPPORTED_CIPHER_ALGOS
from wacryptolib.exceptions import SchemaValidationError, KeystoreAlreadyExists, KeystoreDoesNotExist, ValidationError, \
    KeyDoesNotExist, ExistenceError
from wacryptolib.utilities import get_validation_micro_schemas
from waserver.apps.wagateway.models import PublicAuthenticator, AuthenticatorPublicKey, DecryptionRequest, \
    SymkeyDecryption

from waserver.apps.wagateway.serializers import PublicAuthenticatorSerializer, DecryptionRequestSerializer


def get_public_authenticator(keystore_uid, keystore_secret=None):
    try:
        authenticator_user = PublicAuthenticator.objects.get(keystore_uid=keystore_uid)
        if keystore_secret:
            if keystore_secret != authenticator_user.keystore_secret:
                raise RuntimeError("Wrong authenticator secret")
        return PublicAuthenticatorSerializer(authenticator_user).data
    except PublicAuthenticator.DoesNotExist:
        raise KeystoreDoesNotExist("Authenticator User does not exist")  # TODO change this exception error


def set_public_authenticator(keystore_owner: str, keystore_secret: str, keystore_uid: uuid.UUID, public_keys: list):
    with transaction.atomic():

        public_authenticator_tree = {
            "keystore_owner": keystore_owner,
            "keystore_secret": keystore_secret,
            "keystore_uid": keystore_uid,
            "public_keys": public_keys
        }

        validate_data_tree_with_pythonschema(data_tree=public_authenticator_tree, valid_schema=PUBLIC_AUTHENTICATOR_SCHEMA)

        authenticator_user_or_none = PublicAuthenticator.objects.filter(keystore_uid=keystore_uid).first()

        if authenticator_user_or_none:
            raise KeystoreAlreadyExists("Authenticator %s already exists in sql storage" % keystore_uid)

        public_authenticator = PublicAuthenticator.objects.create(
            keystore_owner=keystore_owner, keystore_uid=keystore_uid)
        public_authenticator.set_keystore_secret(keystore_secret)
        public_authenticator.save()
        for public_key in public_keys:
            AuthenticatorPublicKey.objects.create(authenticator_user=public_authenticator,
                                                  keychain_uid=public_key["keychain_uid"],
                                                  key_algo=public_key["key_algo"],
                                                  key_value=public_key["key_value"])


def submit_decryption_request(keystore_uid: uuid.UUID, requester_uid: uuid.UUID, description: str,
                              response_public_key: bytes,
                              symkeys_decryption: list):
    # symkey_decryption: liste de dict qui ont chacun des champs symkey_ciphertext, key_algo et keychain_uid
    # Tester le cas où les symkeys n'existe pas dans le depôt distant

    # Todo valider le schema

    with transaction.atomic():

        decryption_request_tree = {
            "keystore_uid": keystore_uid,
            "requester_uid": requester_uid,
            "description": description,
            "response_public_key": response_public_key,
            "symkeys_decryption": symkeys_decryption
        }

        validate_data_tree_with_pythonschema(data_tree=decryption_request_tree,
                                             valid_schema=SCHEMA_OF_DECRYTION_RESQUEST_INPUT_PARAMETERS)

        public_authenticator = PublicAuthenticator.objects.filter(keystore_uid=keystore_uid).first()

        if not public_authenticator:
            raise KeystoreDoesNotExist(
                "Authenticator %s does not exists in sql storage" % keystore_uid)  # TODO Create AuthenticatorDoesNotEXIST

        decryption_request = DecryptionRequest.objects.create(authenticator_user=public_authenticator,
                                                              requester_uid=requester_uid,
                                                              description=description,
                                                              response_public_key=response_public_key)

        for symkey_decryption in symkeys_decryption:
            # TODO vérifier que la clé à déchiffrer est présent dans authenticator_public_keys

            try:
                authenticator_public_key = public_authenticator.public_keys.get(
                    keychain_uid=symkey_decryption['keychain_uid'], key_algo=symkey_decryption['key_algo'])
            except AuthenticatorPublicKey.DoesNotExist:
                raise KeyDoesNotExist(
                    "Public key %s does not exists in sql storage" % symkey_decryption['keychain_uid'])

            SymkeyDecryption.objects.create(decryption_request=decryption_request,
                                            authenticator_public_key=authenticator_public_key,
                                            request_data=symkey_decryption["symkey_ciphertext"])


def list_wadevice_decryption_requests(requester_uid):
    try:
        decryption_resquest_of_requester_uid = DecryptionRequest.objects.get(requester_uid=requester_uid)
        # queryset = DecryptionRequest.objects.filter(requester_uid=requester_uid).values('request_status')
        return DecryptionRequestSerializer(decryption_resquest_of_requester_uid).data
    except DecryptionRequest.DoesNotExist:
        raise ExistenceError("Authenticator User does not exist")  # TODO Change this exception


micro_schema = get_validation_micro_schemas(extended_json_format=False)

SCHEMA_OF_DECRYTION_RESQUEST_INPUT_PARAMETERS = Schema({
    "keystore_uid": micro_schema.schema_uid,
    "requester_uid": micro_schema.schema_uid,
    "description": And(str, len),
    "response_public_key": micro_schema.schema_binary,
    "symkeys_decryption": [{
        "symkey_ciphertext": micro_schema.schema_binary,
        "keychain_uid": micro_schema.schema_uid,
        "key_algo": Or(*SUPPORTED_CIPHER_ALGOS),
    }]
})

PUBLIC_AUTHENTICATOR_SCHEMA = Schema({
    "keystore_owner": And(str, len),
    "keystore_secret": And(str, len),
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
