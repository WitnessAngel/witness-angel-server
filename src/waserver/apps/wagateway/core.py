import uuid
from datetime import timedelta
from typing import Optional

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


def submit_decryption_request(keystore_uid: uuid.UUID, requester_uid: uuid.UUID, description: str, response_public_key: bytes,
                              symkeys_decryption: list):
    #symkey_decryption: liste de dict qui ont chacun des champs symkey_ciphertext, key_algo et keychain_uid

    #Todo valider le schema

    with transaction.atomic():

        public_authenticator = PublicAuthenticator.objects.filter(keystore_uid=keystore_uid).first()

        if not public_authenticator:
            raise KeyDoesNotExist("Authenticator %s does not exists in sql storage" % keystore_uid)

        decryption_request = DecryptionRequest.objects.create(
            authenticator_user=public_authenticator, requester_uid=requester_uid, description=description,
                                                              response_public_key=response_public_key)

        #authenticator_public_keys = AuthenticatorPublicKey.objects.filter(authenticator_user=public_authenticator)

        for symkey_decryption in symkeys_decryption:
            # TODO vérifier que la clé à déchiffrer est présent dans authenticator_public_keys

            authenticator_public_key = public_authenticator.public_keys.get(keychain_uid=symkey_decryption['keychain_uid'], key_algo=symkey_decryption['key_algo'])
            #recuperer la bonne clé publique avec public_authenticator.puybli_keys.filter(keychain/keyalgo)....

            SymkeyDecryption.objects.create(decryption_request=decryption_request, authenticator_public_key=authenticator_public_key, request_data=symkey_decryption["symkey_ciphertext"])


def list_wadevice_decryption_requests(requester_uid):
    try:
        queryset = DecryptionRequest.objects.get(requester_uid=requester_uid)
        # queryset = DecryptionRequest.objects.filter(requester_uid=requester_uid).values('request_status')
        return DecryptionRequestSerializer(queryset).data
    except DecryptionRequest.DoesNotExist:
        raise ExistenceError("Authenticator User does not exist") # TODO Change this exception



def _create_public_authenticator_schema():
    """Create validation schema for public authenticator tree

    :return: a schema.
    """
    micro_schema = get_validation_micro_schemas(extended_json_format=False)

    schema_public_authenticator = Schema({
        "keystore_owner": And(str, len),
        "keystore_uid": micro_schema.schema_uid,
        "public_keys": [
            {
                'key_algo': Or(*SUPPORTED_CIPHER_ALGOS),
                'keychain_uid': micro_schema.schema_uid,
                'key_value': micro_schema.schema_binary
            }
        ]
    })

    return schema_public_authenticator


def check_public_authenticator_sanity(public_authenticator: dict):
    """Validate a native python tree of public_authenticator data.

    Raise SchemaValidationError on error
    """
    assert isinstance(public_authenticator, dict), public_authenticator
    public_authenticator_schema = _create_public_authenticator_schema()
    try:
        public_authenticator_schema.validate(public_authenticator)
    except SchemaError as exc:
        raise SchemaValidationError("Error validating public authenticator: {}".format(exc)) from exc
