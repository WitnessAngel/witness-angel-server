import uuid
from datetime import timedelta
from typing import Optional

from django.db import transaction

from schema import And, Or, Schema, SchemaError
from wacryptolib.cipher import SUPPORTED_CIPHER_ALGOS
from wacryptolib.exceptions import SchemaValidationError, KeystoreAlreadyExists, KeystoreDoesNotExist, ValidationError
from wacryptolib.utilities import get_validation_micro_schemas
from waserver.apps.wagateway.models import PublicAuthenticator, AuthenticatorPublicKey, DecryptionRequest, \
    SymkeyDecryption

from waserver.apps.wagateway.serializers import PublicAuthenticatorSerializer


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


def submit_decryption_request(authenticator_user, requester_uid, description, response_public_key, request_status,
                              list_Symkey_Decryption: list):
    with transaction.atomic():
        queryset = DecryptionRequest.objects.filter(requester_uid=requester_uid)
        for symkey_decryption in list_Symkey_Decryption:
            if symkey_decryption["request_data"] == SymkeyDecryption.objects.filter(
                    request_data=symkey_decryption["request_data"]):
                raise ValidationError('Une demande à déja été effectué pour cette clé')
            DecryptionRequest.objects.create(authenticator_user, requester_uid, description, response_public_key,
                                             request_status)
            SymkeyDecryption.objects.create(symkey_decryption["decryption_request"],
                                            symkey_decryption["symkey_decryption"],
                                            symkey_decryption["cryptainer_metadata"], symkey_decryption["request_data"],
                                            symkey_decryption["response_data"], symkey_decryption["decryption_status"])


def list_wadevice_decryption_requests(requester_uid):
    queryset = DecryptionRequest.objects.filter(requester_uid=requester_uid)
    return queryset


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
