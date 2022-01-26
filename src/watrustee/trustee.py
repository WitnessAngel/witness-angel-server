import pickle
import pprint
import threading
import uuid
from datetime import timedelta
from typing import Optional

from django.db import transaction
from django.utils import timezone

import jsonschema
from jsonschema import validate
from schema import And, Or, Regex, Const, Schema
from wacryptolib.cipher import SUPPORTED_CIPHER_ALGOS
from wacryptolib.keystore import KeystoreReadWriteBase

from wacryptolib.trustee import TrusteeApi
from wacryptolib.exceptions import KeyDoesNotExist, KeyAlreadyExists, AuthorizationError, ExistenceError, \
    SchemaValidationError, OperationNotSupported
from wacryptolib.utilities import synchronized

from watrustee.models import TrusteeKeypair, DECRYPTION_AUTHORIZATION_LIFESPAN_H, \
    AuthenticatorPublicKey, PublicAuthenticator
from watrustee.serializers import PublicAuthenticatorSerializer


def _fetch_key_object_or_none(keychain_uid: uuid.UUID, key_algo: str) -> TrusteeKeypair:
    return TrusteeKeypair.objects.filter(keychain_uid=keychain_uid, key_algo=key_algo).first()


def _fetch_key_object_or_raise(keychain_uid: uuid.UUID, key_algo: str) -> TrusteeKeypair:
    keypair_obj = _fetch_key_object_or_none(keychain_uid=keychain_uid, key_algo=key_algo)
    if not keypair_obj:
        raise KeyDoesNotExist("Keypair %s/%s not found in database" % (keychain_uid, key_algo))
    return keypair_obj


def get_public_authenticator(keystore_uid, keystore_secret=None):
    try:
        authenticator_user = PublicAuthenticator.objects.get(keystore_uid=keystore_uid)
        if keystore_secret:
            if keystore_secret != authenticator_user.keystore_secret:
                raise RuntimeError("Wrong authenticator secret")
        return PublicAuthenticatorSerializer(authenticator_user).data
    except PublicAuthenticator.DoesNotExist:
        raise ExistenceError("Authenticator User does not exist")  # TODO change this exception error


def set_public_authenticator(keystore_owner: str, keystore_secret: str, keystore_uid: uuid.UUID, public_keys: list):
    with transaction.atomic():
        authenticator_user_or_none = PublicAuthenticator.objects.filter(keystore_uid=keystore_uid).first()

        if authenticator_user_or_none:
            # for public_key in public_keys: AuthenticatorPublicKey.objects.create(
            # authenticator_user=authenticator_user_exist_or_none,keychain_uid=public_key["keychain_uid"],
            # key_algo=public_key["key_algo"], payload=public_key["payload"])

            raise KeyDoesNotExist("Authenticator already exists in sql storage" % keystore_uid)

        user = PublicAuthenticator.objects.create(keystore_owner=keystore_owner,
                                                  keystore_secret=keystore_secret, keystore_uid=keystore_uid)
        for public_key in public_keys:
            AuthenticatorPublicKey.objects.create(authenticator_user=user,
                                                  keychain_uid=public_key["keychain_uid"],
                                                  key_algo=public_key["key_algo"], payload=public_key["payload"])


def _create_public_authenticator_extended_json_schema():
    """Create validation schema for public authenticator tree

    :return: a schema.
    """

    # FIXME deduplicate that from wacryptolib!
    _micro_schema_base64 = And(str, Regex(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})'))
    micro_schema_uid = {
        "$binary": {
            "base64": _micro_schema_base64,
            "subType": "03"}}
    micro_schema_binary = {
        "$binary": {
            "base64": _micro_schema_base64,
            "subType": "00"}
    }

    schema_public_authenticator = Schema({
        "keystore_owner": And(str, len),
        "keystore_uid": micro_schema_uid,
        "public_keys": [
            {
                'key_algo': Or(*SUPPORTED_CIPHER_ALGOS),
                'keychain_uid': micro_schema_uid,
                'payload': micro_schema_binary
            }
        ]
    })

    return schema_public_authenticator


def check_public_authenticator_sanity(public_authenticator: dict):
    assert isinstance(public_authenticator, dict)
    public_authenticator_schema_tree = _create_public_authenticator_extended_json_schema().json_schema("schema_public_authenticator")
    try:
        validate(instance=public_authenticator, schema=public_authenticator_schema_tree)
    except jsonschema.exceptions.ValidationError as exc:
        raise SchemaValidationError("Error validating public authenticator: {}".format(exc)) from exc


class SqlKeystore(KeystoreReadWriteBase):
    """
    Store keys in records of SQL DB.

    Since SQLITE has bad support for concurrent transactions and isolation levels, we rely on
    in-process locks to prevent lost updates, but it also means that this storage is
    NOT MULTI-PROCESS SAFE!
    """

    # TODO - ensure the secret key of Django DB storage is given by environment variable for security?

    def _public_key_exists(self, *, keychain_uid, key_algo):
        keypair_obj = _fetch_key_object_or_none(keychain_uid=keychain_uid, key_algo=key_algo)
        return bool(keypair_obj)

    def _private_key_exists(self, *, keychain_uid, key_algo):
        keypair_obj = _fetch_key_object_or_none(keychain_uid=keychain_uid, key_algo=key_algo)
        return bool(keypair_obj and keypair_obj.private_key)

    def _get_public_key(self, *, keychain_uid, key_algo):
        keypair_obj = _fetch_key_object_or_none(keychain_uid=keychain_uid, key_algo=key_algo)
        assert keypair_obj and keypair_obj.public_key  # Non nullable
        return keypair_obj.public_key

    def _get_private_key(self, *, keychain_uid, key_algo):
        keypair_obj = _fetch_key_object_or_none(keychain_uid=keychain_uid, key_algo=key_algo)
        assert keypair_obj and keypair_obj.private_key
        return keypair_obj.private_key

    def _list_unordered_keypair_identifiers(self):
        raise OperationNotSupported

    def _set_public_key(self, *, keychain_uid, key_algo, public_key):
        TrusteeKeypair.objects.create(
            keychain_uid=keychain_uid,
            key_algo=key_algo,
            public_key=public_key,
            private_key=None,
        )

    def _set_private_key(self, *, keychain_uid, key_algo, private_key):
        keypair_obj = _fetch_key_object_or_none(keychain_uid=keychain_uid, key_algo=key_algo)
        assert keypair_obj and keypair_obj.public_key
        keypair_obj.private_key = private_key
        keypair_obj.save()

    def _get_free_keypairs_count(self, key_algo):
        assert key_algo, key_algo
        return TrusteeKeypair.objects.filter(
            keychain_uid=None, key_algo=key_algo
        ).count()

    def _add_free_keypair(self, *, key_algo, public_key, private_key):
        TrusteeKeypair.objects.create(
            keychain_uid=None,
            key_algo=key_algo,
            public_key=public_key,
            private_key=private_key,
        )

    def _attach_free_keypair_to_uuid(self, *, keychain_uid, key_algo):
        # Beware, SPECIAL LOOKUP for the first available free key, here
        keypair_obj_or_none = TrusteeKeypair.objects.filter(
            keychain_uid=None, key_algo=key_algo
        ).first()
        if not keypair_obj_or_none:
            raise KeyDoesNotExist(
                "No free keypair of type %s available in sql storage" % key_algo
            )
        keypair_obj_or_none.keychain_uid = keychain_uid
        keypair_obj_or_none.attached_at = timezone.now()
        keypair_obj_or_none.save()


class SqlTrusteeApi(TrusteeApi):
    DECRYPTION_AUTHORIZATION_GRACE_PERIOD_S = 5 * 60

    def decrypt_with_private_key(self, keychain_uid, cipher_algo, cipherdict, passphrases: Optional[list] = None):
        """
        This implementation checks for a dedicated timestamp flag on the keypair, in DB, and
        only allows decryption for a certain time after that timestamp.
        """
        del passphrases  # For now, SQL keypairs are never passphrase-protected

        # TODO - a redesign of the API could prevent the double DB lookup here, but not sure if it's useful on the long term...
        keypair_obj = _fetch_key_object_or_raise(
            keychain_uid=keychain_uid, key_algo=cipher_algo
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
            cipher_algo=cipher_algo,
            cipherdict=cipherdict,
        )

    def request_decryption_authorization(self, keypair_identifiers, request_message, passphrases=None):
        """
        This implementation only activates the dedicated timestamp flag, in DB, for the targeted keypairs,
        if the keypair has been attached to the keychain uid for a small amount of time.

        A possibly already existing dedicated timestamp flag is ignorzed, so this method could return negative results
        even if a previously given authorization is still valid.
        """

        del passphrases  # Unused in this kind of remote trustee

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
                    key_algo=keypair_identifier["key_algo"],
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



SQL_TRUSTEE_API = SqlTrusteeApi(keystore=SqlKeystore())
