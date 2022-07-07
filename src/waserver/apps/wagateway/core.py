import uuid

from django.db import transaction
from schema import And, Or, Optional, Schema, SchemaError

from wacryptolib.cipher import SUPPORTED_CIPHER_ALGOS
from wacryptolib.exceptions import (
    SchemaValidationError,
    KeystoreAlreadyExists,
    KeyDoesNotExist,
    ExistenceError,
    AuthenticationError,
    AuthenticatorDoesNotExist,
    ValidationError,
)
from wacryptolib.utilities import get_validation_micro_schemas
from waserver.apps.wagateway.models import (
    PublicAuthenticator,
    PublicAuthenticatorKey,
    RevelationRequest,
    SymkeyDecryptionRequest,
    RevelationRequestStatus,
    SymkeyDecryptionStatus,
)
from waserver.apps.wagateway.serializers import PublicAuthenticatorSerializer, RevelationRequestSerializer


def _validate_public_authenticator_secret(public_authenticator, keystore_secret):
    secret_is_correct = public_authenticator.check_keystore_secret(keystore_secret)
    if not secret_is_correct:
        raise AuthenticationError("The provided keystore secret is not correct for target authenticator")


def _get_public_authenticator_by_keystore_uid(keystore_uid):
    try:
        public_authenticator = PublicAuthenticator.objects.get(keystore_uid=keystore_uid)
    except PublicAuthenticator.DoesNotExist:
        raise AuthenticatorDoesNotExist("Authenticator %s does not exist in database" % keystore_uid) from None
    return public_authenticator


def _get_authorized_revelation_request_by_request_uid(revelation_request_uid, authenticator_keystore_secret):
    try:
        revelation_request = RevelationRequest.objects.get(revelation_request_uid=revelation_request_uid)
    except RevelationRequest.DoesNotExist:
        raise ExistenceError(
            "Revelation request %s does not exist" % revelation_request_uid
        )  # TODO Change this exception?

    _validate_public_authenticator_secret(
        revelation_request.target_public_authenticator, keystore_secret=authenticator_keystore_secret
    )
    return revelation_request


def get_public_authenticator(keystore_uid, keystore_secret=None):

    validate_data_tree_with_pythonschema(
        dict(keystore_uid=keystore_uid, keystore_secret=keystore_secret),
        Schema({"keystore_uid": micro_schemas.schema_uid, "keystore_secret": Or(None, str)}),
    )

    public_authenticator = _get_public_authenticator_by_keystore_uid(keystore_uid)

    if keystore_secret:  # Optional, only provided to check if owned keystore_secret is still OK
        _validate_public_authenticator_secret(public_authenticator, keystore_secret=keystore_secret)

    return PublicAuthenticatorSerializer(public_authenticator).data


def set_public_authenticator(keystore_uid: uuid.UUID, keystore_owner: str, public_keys: list, keystore_secret: str):

    with transaction.atomic():

        public_authenticator_tree = {
            "keystore_uid": keystore_uid,
            "keystore_owner": keystore_owner,
            "public_keys": public_keys,
            "keystore_secret": keystore_secret,
        }

        validate_data_tree_with_pythonschema(
            data_tree=public_authenticator_tree, valid_schema=PUBLIC_AUTHENTICATOR_SCHEMA
        )

        try:
            PublicAuthenticator.objects.get(keystore_uid=keystore_uid)
            raise KeystoreAlreadyExists("Authenticator %s already exists in database" % keystore_uid)
        except PublicAuthenticator.DoesNotExist:
            public_authenticator = PublicAuthenticator(keystore_owner=keystore_owner, keystore_uid=keystore_uid)
            public_authenticator.set_keystore_secret(keystore_secret)
            public_authenticator.save()
            for public_key in public_keys:
                PublicAuthenticatorKey.objects.create(
                    public_authenticator=public_authenticator,
                    keychain_uid=public_key["keychain_uid"],
                    key_algo=public_key["key_algo"],
                    key_value=public_key["key_value"],
                )


def submit_revelation_request(
    authenticator_keystore_uid: uuid.UUID,
    revelation_requestor_uid: uuid.UUID,
    revelation_request_description: str,
    revelation_response_public_key: bytes,
    revelation_response_keychain_uid: uuid.UUID,
    revelation_response_key_algo: str,
    symkey_decryption_requests: list,
):
    # TODO Ensure that the different symkey "request_data" are unique for the same revelation request
    with transaction.atomic():

        revelation_request_tree = {
            "authenticator_keystore_uid": authenticator_keystore_uid,
            "revelation_requestor_uid": revelation_requestor_uid,
            "revelation_request_description": revelation_request_description,
            "revelation_response_public_key": revelation_response_public_key,
            "revelation_response_keychain_uid": revelation_response_keychain_uid,
            "revelation_response_key_algo": revelation_response_key_algo,
            "symkey_decryption_requests": symkey_decryption_requests,
        }

        validate_data_tree_with_pythonschema(
            data_tree=revelation_request_tree, valid_schema=REVELATION_REQUEST_INPUT_PARAMETERS_SCHEMA
        )

        target_public_authenticator = _get_public_authenticator_by_keystore_uid(authenticator_keystore_uid)

        revelation_request = RevelationRequest.objects.create(
            target_public_authenticator=target_public_authenticator,
            revelation_requestor_uid=revelation_requestor_uid,
            revelation_request_description=revelation_request_description,
            revelation_response_public_key=revelation_response_public_key,
            revelation_response_keychain_uid=revelation_response_keychain_uid,
            revelation_response_key_algo=revelation_response_key_algo,
        )

        for symkey_decryption_request in symkey_decryption_requests:

            try:
                target_public_authenticator_key = target_public_authenticator.public_keys.get(
                    keychain_uid=symkey_decryption_request["keychain_uid"],
                    key_algo=symkey_decryption_request["key_algo"],
                )
            except PublicAuthenticatorKey.DoesNotExist:
                raise KeyDoesNotExist(
                    "Public key %s does not exist in key storage for authenticator %s"
                    % (symkey_decryption_request["keychain_uid"], authenticator_keystore_uid)
                )

            SymkeyDecryptionRequest.objects.create(
                revelation_request=revelation_request,
                cryptainer_uid=symkey_decryption_request["cryptainer_uid"],
                cryptainer_metadata=symkey_decryption_request["cryptainer_metadata"],
                target_public_authenticator_key=target_public_authenticator_key,
                symkey_decryption_request_data=symkey_decryption_request["symkey_decryption_request_data"],
            )


def list_requestor_revelation_requests(revelation_requestor_uid: uuid.UUID):
    # Called by NVR and other WA revelation-station software

    validate_data_tree_with_pythonschema(
        dict(revelation_requestor_uid=revelation_requestor_uid),
        Schema({"revelation_requestor_uid": micro_schemas.schema_uid}),
    )

    revelation_requests_for_requestor_uid = RevelationRequest.objects.filter(
        revelation_requestor_uid=revelation_requestor_uid
    ).prefetch_related("symkey_decryption_requests")

    return RevelationRequestSerializer(revelation_requests_for_requestor_uid, many=True).data


def list_authenticator_revelation_requests(authenticator_keystore_uid: uuid.UUID, authenticator_keystore_secret: str):
    # Called by authenticator, authenticated with keystore secret

    validate_data_tree_with_pythonschema(
        dict(
            authenticator_keystore_uid=authenticator_keystore_uid,
            authenticator_keystore_secret=authenticator_keystore_secret,
        ),
        Schema({"authenticator_keystore_uid": micro_schemas.schema_uid, "authenticator_keystore_secret": str}),
    )

    target_public_authenticator = _get_public_authenticator_by_keystore_uid(authenticator_keystore_uid)
    _validate_public_authenticator_secret(target_public_authenticator, keystore_secret=authenticator_keystore_secret)

    revelation_requests_for_keystore_uid = RevelationRequest.objects.filter(
        target_public_authenticator__keystore_uid=authenticator_keystore_uid
    ).prefetch_related("symkey_decryption_requests")

    return RevelationRequestSerializer(revelation_requests_for_keystore_uid, many=True).data


def reject_revelation_request(revelation_request_uid: uuid.UUID, authenticator_keystore_secret: str):
    """Called by authenticator, and authenticated with keystore secret"""

    validate_data_tree_with_pythonschema(
        dict(
            revelation_request_uid=revelation_request_uid, authenticator_keystore_secret=authenticator_keystore_secret
        ),
        Schema({"revelation_request_uid": micro_schemas.schema_uid, "authenticator_keystore_secret": str}),
    )

    with transaction.atomic():
        revelation_request = _get_authorized_revelation_request_by_request_uid(
            revelation_request_uid, authenticator_keystore_secret=authenticator_keystore_secret
        )

        if revelation_request.revelation_request_status != RevelationRequestStatus.PENDING:
            raise ValidationError(
                "Cannot reject a revelation request in status %s" % revelation_request.revelation_request_status
            )

        revelation_request.revelation_request_status = RevelationRequestStatus.REJECTED
        revelation_request.save()


def accept_revelation_request(
    revelation_request_uid: uuid.UUID, authenticator_keystore_secret: str, symkey_decryption_results: list
):
    """Called by authenticator, and authenticated with keystore secret"""

    validate_data_tree_with_pythonschema(
        dict(
            revelation_request_uid=revelation_request_uid,
            authenticator_keystore_secret=authenticator_keystore_secret,
            symkey_decryption_results=symkey_decryption_results,
        ),
        Schema(
            {
                "revelation_request_uid": micro_schemas.schema_uid,
                "authenticator_keystore_secret": str,
                "symkey_decryption_results": And(
                    len,
                    [
                        {
                            "symkey_decryption_request_data": micro_schemas.schema_binary,
                            "symkey_decryption_response_data": micro_schemas.schema_binary,
                            "symkey_decryption_status": Or(
                                *(set(SymkeyDecryptionStatus.values) - {SymkeyDecryptionStatus.PENDING})
                            ),
                        }
                    ],
                ),
            }
        ),
    )

    with transaction.atomic():

        revelation_request = _get_authorized_revelation_request_by_request_uid(
            revelation_request_uid, authenticator_keystore_secret=authenticator_keystore_secret
        )

        if revelation_request.revelation_request_status != RevelationRequestStatus.PENDING:
            raise ValidationError(
                "Cannot accept a revelation request in status %s" % revelation_request.revelation_request_status
            )

        symkey_decryption_requests = revelation_request.symkey_decryption_requests.all()

        expected_request_data = set(
            (symkey_decryption_request.symkey_decryption_request_data, symkey_decryption_request.target_public_authenticator_key_id)
            for symkey_decryption_request in symkey_decryption_requests
        )

        received_request_data = set(
            (symkey_decryption_request.symkey_decryption_request_data, symkey_decryption_request.target_public_authenticator_key_id)
            symkey_decryption_result["symkey_decryption_request_data"]
            for symkey_decryption_result in symkey_decryption_results
        )

        if received_request_data != expected_request_data:
            exceeding_request_data_among_received = received_request_data - expected_request_data
            missing_request_data_among_received = expected_request_data - received_request_data
            assert exceeding_request_data_among_received or missing_request_data_among_received
            raise ValidationError(
                "Difference between expected and received symkey_decryption_results, "
                "%s is received but unexpected and %s is expected but not received"
                % (exceeding_request_data_among_received, missing_request_data_among_received)
            )

        # Ensure it's "all or nothing" for response data
        for symkey_decryption_result in symkey_decryption_results:
            assert (
                symkey_decryption_result["symkey_decryption_status"] != SymkeyDecryptionStatus.PENDING
            )  # Schema must ensure that above
            if (
                symkey_decryption_result["symkey_decryption_status"] == SymkeyDecryptionStatus.DECRYPTED
                and symkey_decryption_result["symkey_decryption_response_data"]
            ):
                pass
            elif (
                symkey_decryption_result["symkey_decryption_status"] != SymkeyDecryptionStatus.DECRYPTED
                and not symkey_decryption_result["symkey_decryption_response_data"]
            ):
                pass
            else:
                raise ValidationError(
                    "Incoherence between symkey_decryption_status=%s and presence of symkey_decryption_response_data"
                    % symkey_decryption_result["symkey_decryption_status"]
                )

        for symkey_decryption_request in symkey_decryption_requests:

            for symkey_decryption_result in symkey_decryption_results:

                if (
                    symkey_decryption_request.symkey_decryption_request_data
                    == symkey_decryption_result["symkey_decryption_request_data"]
                ):
                    symkey_decryption_request.symkey_decryption_response_data = symkey_decryption_result[
                        "symkey_decryption_response_data"
                    ]
                    symkey_decryption_request.symkey_decryption_status = symkey_decryption_result[
                        "symkey_decryption_status"
                    ]
                    symkey_decryption_request.save()

        revelation_request.revelation_request_status = RevelationRequestStatus.ACCEPTED
        revelation_request.save()


micro_schemas = get_validation_micro_schemas(extended_json_format=False)

REVELATION_REQUEST_INPUT_PARAMETERS_SCHEMA = Schema(
    {
        "authenticator_keystore_uid": micro_schemas.schema_uid,
        "revelation_requestor_uid": micro_schemas.schema_uid,
        "revelation_request_description": And(str, len),
        "revelation_response_public_key": micro_schemas.schema_binary,
        "revelation_response_keychain_uid": micro_schemas.schema_uid,
        "revelation_response_key_algo": Or(*SUPPORTED_CIPHER_ALGOS),
        "symkey_decryption_requests": [
            {
                "cryptainer_uid": micro_schemas.schema_uid,
                "cryptainer_metadata": Or(dict, None),
                "symkey_decryption_request_data": micro_schemas.schema_binary,
                "keychain_uid": micro_schemas.schema_uid,
                "key_algo": Or(*SUPPORTED_CIPHER_ALGOS),
            }
        ],
    }
)

PUBLIC_AUTHENTICATOR_SCHEMA = Schema(
    {
        "keystore_owner": And(str, len),
        Optional("keystore_secret"): And(str, len),
        "keystore_uid": micro_schemas.schema_uid,
        "public_keys": And(
            [
                {
                    "keychain_uid": micro_schemas.schema_uid,
                    "key_algo": Or(*SUPPORTED_CIPHER_ALGOS),
                    "key_value": micro_schemas.schema_binary,
                }
            ],
            len,
        ),
    }
)


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
