import pickle
import threading
import uuid
from datetime import timedelta
from typing import Optional

from django.utils import timezone

import jsonschema
from jsonschema import validate
from schema import And, Or, Regex, Const, Schema
from wacryptolib.encryption import SUPPORTED_ENCRYPTION_ALGOS

from wacryptolib.escrow import KeyStorageBase, EscrowApi
from wacryptolib.exceptions import KeyDoesNotExist, KeyAlreadyExists, AuthorizationError, ExistenceError, \
    ValidationError
from wacryptolib.utilities import synchronized

from waescrow.models import AuthenticatorUser, EscrowKeypair, DECRYPTION_AUTHORIZATION_LIFESPAN_H, \
    AuthenticatorPublicKey
from waescrow.serializers import AuthenticatorUserSerializer


def _fetch_key_object_or_raise(keychain_uid: uuid.UUID, key_type: str) -> EscrowKeypair:
    try:
        return EscrowKeypair.objects.get(keychain_uid=keychain_uid, key_type=key_type)
    except EscrowKeypair.DoesNotExist:
        raise KeyDoesNotExist("Database keypair %s/%s not found" % (keychain_uid, key_type))


def get_public_authenticator(username, authenticator_secret):
    try:
        authenticator_user = AuthenticatorUser.objects.get(username=username)
        assert authenticator_secret == authenticator_user.authenticator_secret
        return AuthenticatorUserSerializer(authenticator_user).data
    except EscrowKeypair.DoesNotExist:
        raise ExistenceError("Authenticator User does not exist")  # TODO change this exception error


def set_public_authenticator(description: str, authenticator_secret: str, username: str, public_keys: list):
    authenticator_user_exist_or_none = AuthenticatorUser.objects.filter(username=username).first()

    if authenticator_user_exist_or_none:
        raise KeyDoesNotExist("Authenticator already exists in sql storage" % username)
    else:
        user = AuthenticatorUser.objects.create(description=description,
                                                authenticator_secret=authenticator_secret, username=username)
        for public_key in public_keys:
            AuthenticatorPublicKey.objects.create(authenticator_user=user,
                                                  keychain_uid=public_key["keychain_uid"],
                                                  key_type=public_key["key_type"], payload=public_key["payload"])


def _create_schema():
    """Create validation schema for confs and containers.

    :return: a schema.
    """

    _micro_schema_hex_uid = And(str, Or(Regex(
        '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$'), Regex(
        '[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}')))
    micro_schema_uid = {
        "$binary": {
            "base64": _micro_schema_hex_uid,
            "subType": "03"}}
    micro_schema_binary = {
        "$binary": {
            "base64": And(str,
                          Regex('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$')),
            "subType": "00"}
    }

    SCHEMA_PUBLIC_AUTHENTICATOR = Schema({
        "description": And(str, len),
        "username": And(str, len),
        "public_keys": [
            {
                'key_type': Or(*SUPPORTED_ENCRYPTION_ALGOS),
                'keychain_uid': micro_schema_uid,
                'payload': micro_schema_binary
            }
        ]
    })

    return SCHEMA_PUBLIC_AUTHENTICATOR


def check_public_authenticator_sanity(public_authenticator: dict):
    assert isinstance(public_authenticator, dict)
    public_authenticator_schema_tree = _create_schema().json_schema("schema_test")
    try:
        validate(instance=public_authenticator, schema=public_authenticator_schema_tree)
    except jsonschema.exceptions.ValidationError as exc:
        raise ValidationError("Error validating with {}".format(exc)) from exc


class SqlKeyStorage(KeyStorageBase):
    """
    Store keys in records of SQL DB.

    Since SQLITE has bad support for concurrent transactions and isolation levels, we rely on
    in-process locks to prevent lost updates, but it also means that this storage is
    NOT MULTI-PROCESS SAFE!
    """

    # TODO - ensure the secret key of Django DB storage is given by environment variable for security?

    _lock = threading.Lock()  # Process-wide lock

    def _ensure_keypair_does_not_exist(self, keychain_uid: uuid.UUID, key_type: str):
        # program might still raise IntegrityError if the same key is inserted concurrently
        try:
            _fetch_key_object_or_raise(keychain_uid=keychain_uid, key_type=key_type)
        except KeyDoesNotExist:
            pass  # All is fine
        else:
            raise KeyAlreadyExists(
                "Already existing sql keypair %s/%s" % (keychain_uid, key_type)
            )

    @synchronized
    def set_keys(self, *, keychain_uid: uuid.UUID, key_type: str, public_key: bytes, private_key: bytes, ):
        self._ensure_keypair_does_not_exist(
            keychain_uid=keychain_uid, key_type=key_type
        )
        EscrowKeypair.objects.create(
            keychain_uid=keychain_uid,
            key_type=key_type,
            public_key=public_key,
            private_key=private_key,
        )

    @synchronized
    def get_public_key(self, *, keychain_uid: uuid.UUID, key_type: str) -> bytes:
        keypair_obj = _fetch_key_object_or_raise(
            keychain_uid=keychain_uid, key_type=key_type
        )
        return keypair_obj.public_key

    @synchronized
    def get_private_key(self, *, keychain_uid: uuid.UUID, key_type: str) -> bytes:
        keypair_obj = _fetch_key_object_or_raise(
            keychain_uid=keychain_uid, key_type=key_type
        )
        return keypair_obj.private_key

    @synchronized
    def get_free_keypairs_count(self, key_type: str) -> int:  # pragma: no cover
        assert key_type, key_type
        return EscrowKeypair.objects.filter(
            keychain_uid=None, key_type=key_type
        ).count()

    @synchronized
    def add_free_keypair(self, *, key_type: str, public_key: bytes, private_key: bytes):
        EscrowKeypair.objects.create(
            keychain_uid=None,
            key_type=key_type,
            public_key=public_key,
            private_key=private_key,
        )

    @synchronized
    def attach_free_keypair_to_uuid(self, *, keychain_uid: uuid.UUID, key_type: str):
        self._ensure_keypair_does_not_exist(
            keychain_uid=keychain_uid, key_type=key_type
        )

        # Beware, SPECIAL LOOKUP for the first available free key, here
        keypair_obj_or_none = EscrowKeypair.objects.filter(
            keychain_uid=None, key_type=key_type
        ).first()
        if not keypair_obj_or_none:
            raise KeyDoesNotExist(
                "No free keypair of type %s available in sql storage" % key_type
            )
        keypair_obj_or_none.keychain_uid = keychain_uid
        keypair_obj_or_none.attached_at = timezone.now()
        keypair_obj_or_none.save()


class SqlEscrowApi(EscrowApi):
    DECRYPTION_AUTHORIZATION_GRACE_PERIOD_S = 5 * 60

    def decrypt_with_private_key(self, keychain_uid, encryption_algo, cipherdict, passphrases: Optional[list] = None):
        """
        This implementation checks for a dedicated timestamp flag on the keypair, in DB, and
        only allows decryption for a certain time after that timestamp.
        """
        del passphrases  # For now, SQL keypairs are never passphrase-protected

        # TODO - a redesign of the API could prevent the double DB lookup here, but not sure if it's useful on the long term...
        keypair_obj = _fetch_key_object_or_raise(
            keychain_uid=keychain_uid, key_type=encryption_algo
        )
        decryption_authorized_at = keypair_obj.decryption_authorized_at

        if not decryption_authorized_at:
            raise AuthorizationError(
                "Decryption not authorized"
            )

        decryption_authorized_until = decryption_authorized_at + timedelta(
            hours=DECRYPTION_AUTHORIZATION_LIFESPAN_H
        )

        now = timezone.now()
        _format_datetime = lambda dt: dt.isoformat(sep="_", timespec="seconds")

        if not (decryption_authorized_at <= now <= decryption_authorized_until):
            raise AuthorizationError(
                "Decryption authorization is only valid from %s to %s (current time: %s)"
                % (
                    _format_datetime(decryption_authorized_at),
                    _format_datetime(decryption_authorized_until),
                    _format_datetime(now),
                )
            )

        return super().decrypt_with_private_key(
            keychain_uid=keychain_uid,
            encryption_algo=encryption_algo,
            cipherdict=cipherdict,
        )

    def request_decryption_authorization(self, keypair_identifiers, request_message, passphrases=None):
        """
        This implementation only activates the dedicated timestamp flag, in DB, for the targeted keypairs,
        if the keypair has been attached to the keychain uid for a small amount of time.

        A possibly already existing dedicated timestamp flag is ignorzed, so this method could return negative results
        even if a previously given authorization is still valid.
        """

        del passphrases  # Unused in this kind of remote escrow

        success_count = 0
        too_old_count = 0
        not_found_count = 0

        now = timezone.now()
        min_attached_at = now - timedelta(
            seconds=self.DECRYPTION_AUTHORIZATION_GRACE_PERIOD_S
        )

        for keypair_identifier in keypair_identifiers:
            try:
                keypair_obj = _fetch_key_object_or_raise(
                    keychain_uid=keypair_identifier["keychain_uid"],
                    key_type=keypair_identifier["key_type"],
                )
            except KeyDoesNotExist:
                not_found_count += 1
                continue

            # Different times for pregenerated and on-demand keys
            attached_at = keypair_obj.attached_at or keypair_obj.created_at

            if attached_at < min_attached_at:
                too_old_count += 1
                continue

            # SUCCESS case
            keypair_obj.decryption_authorized_at = (
                now
            )  # Might renew existing authorization
            keypair_obj.save()
            success_count += 1

        response_message = f"Authorization provided to {success_count} key pairs for {DECRYPTION_AUTHORIZATION_LIFESPAN_H}h, rejected for {too_old_count} key pairs due to age, and impossible for {not_found_count} key pairs not found"

        return dict(
            response_message=response_message,
            success_count=success_count,
            too_old_count=too_old_count,
            not_found_count=not_found_count,
        )


SQL_ESCROW_API = SqlEscrowApi(key_storage=SqlKeyStorage())
