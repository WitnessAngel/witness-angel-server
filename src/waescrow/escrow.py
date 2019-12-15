import threading
import uuid
from datetime import timedelta

from django.utils import timezone

from wacryptolib.escrow import KeyStorageBase, EscrowApi
from wacryptolib.utilities import synchronized
from waescrow.models import EscrowKeypair, DECRYPTION_AUTHORIZATION_LIFESPAN_H


# TODO add "fetch object which must exist" utility method!
def _fetch_key_object_or_none(keychain_uid: uuid.UUID, key_type: str) -> EscrowKeypair:
    try:
        return EscrowKeypair.objects.get(keychain_uid=keychain_uid, key_type=key_type)
    except EscrowKeypair.DoesNotExist:
        return None


class SqlKeyStorage(KeyStorageBase):
    """
    Store keys in records of SQL DB.

    Since SQLITE has bad support for concurrent transactions and isolation levels, we rely on
    in-process locks to prevent lost updates, but it also means that this storage is
    NOT MULTI-PROCESS SAFE!
    """

    # TODO - ensure the secret key of Django DB storage is given by environment variable for security?

    _lock = threading.Lock()  # Process-wide lock

    def _ensure_keypair_does_not_exist(self, keychain_uid, key_type):
        # program might still raise IntegrityError if the same key is inserted concurrently
        if _fetch_key_object_or_none(keychain_uid=keychain_uid, key_type=key_type):
            raise RuntimeError(
                "Already existing sql keypair %s/%s" % (keychain_uid, key_type)
            )

    @synchronized
    def set_keys(self, *, keychain_uid: uuid.UUID, key_type: str, public_key: bytes, private_key: bytes):
        self._ensure_keypair_does_not_exist(keychain_uid=keychain_uid, key_type=key_type)
        EscrowKeypair.objects.create(keychain_uid=keychain_uid, key_type=key_type,
                                     public_key=public_key, private_key=private_key)

    @synchronized
    def get_public_key(self, *, keychain_uid: uuid.UUID, key_type: str) -> bytes:
        keypair_obj_or_none = _fetch_key_object_or_none(keychain_uid=keychain_uid, key_type=key_type)
        return keypair_obj_or_none.public_key if keypair_obj_or_none else None

    @synchronized
    def get_private_key(self, *, keychain_uid: uuid.UUID, key_type: str) -> bytes:
        keypair_obj_or_none = _fetch_key_object_or_none(keychain_uid=keychain_uid, key_type=key_type)
        return keypair_obj_or_none.private_key if keypair_obj_or_none else None

    @synchronized
    def get_free_keypairs_count(self, key_type: str) -> int:  # pragma: no cover
        assert key_type, key_type
        return EscrowKeypair.objects.filter(keychain_uid=None, key_type=key_type).count()

    @synchronized
    def add_free_keypair(
        self, *, key_type: str, public_key: bytes, private_key: bytes
    ):
        EscrowKeypair.objects.create(keychain_uid=None, key_type=key_type,
                                     public_key=public_key, private_key=private_key)

    @synchronized
    def attach_free_keypair_to_uuid(
        self, *, keychain_uid: uuid.UUID, key_type: str
    ):
        self._ensure_keypair_does_not_exist(keychain_uid=keychain_uid, key_type=key_type)

        # Beware, SPECIAL LOOKUP for the first available free key, here
        keypair_obj_or_none = EscrowKeypair.objects.filter(keychain_uid=None, key_type=key_type).first()
        if not keypair_obj_or_none:
            raise RuntimeError(
                "No free keypair of type %s available in sql storage" % key_type
            )
        keypair_obj_or_none.keychain_uid = keychain_uid
        keypair_obj_or_none.save()


class SqlEscrowApi(EscrowApi):

    DECRYPTION_AUTHORIZATION_GRACE_PERIOD_S = 5 * 60

    def decrypt_with_private_key(self,
            keychain_uid,
            encryption_algo,
            cipherdict):

        # TODO - a redesign of the API could prevent the double DB lookup here, but not sure if it's useful on the long term...
        keypair_obj_or_none = _fetch_key_object_or_none(keychain_uid=keychain_uid, key_type=encryption_algo)
        if not keypair_obj_or_none:  # Redundant with checks in decrypt_with_private_key()
            raise ValueError("Unexisting sql keypair %s/%s in SQL escrow api" % (keychain_uid, encryption_algo))

        decryption_authorized_at = keypair_obj_or_none.decryption_authorized_at

        if not decryption_authorized_at:
            raise RuntimeError("Decryption not authorized")  # TODO better exception class

        decryption_authorized_until = decryption_authorized_at + timedelta(hours=DECRYPTION_AUTHORIZATION_LIFESPAN_H)

        now = timezone.now()
        _format_datetime =  lambda dt: dt.isoformat(sep="_", timespec="seconds")

        if not (decryption_authorized_at <= now <= decryption_authorized_until):
            raise RuntimeError("Decryption authorization is only valid from %s to %s (current time: %s)" %
                               (_format_datetime(decryption_authorized_at),
                                _format_datetime(decryption_authorized_until),
                                _format_datetime(now)))  # TODO better exception class

        return super().decrypt_with_private_key(keychain_uid=keychain_uid, encryption_algo=encryption_algo, cipherdict=cipherdict)

    def request_decryption_authorization(self,
                                 keypair_identifiers,
                                 request_message):
        success_count = 0
        too_old_count = 0
        not_found_count = 0

        now = timezone.now()
        min_created_at = now - timedelta(seconds=self.DECRYPTION_AUTHORIZATION_GRACE_PERIOD_S)

        for keypair_identifier in keypair_identifiers:
            keypair_obj_or_none = _fetch_key_object_or_none(keychain_uid=keypair_identifier["keychain_uid"],
                                                                 key_type=keypair_identifier["key_type"])
            if keypair_obj_or_none is None:
                not_found_count += 1
                continue
            elif keypair_obj_or_none.created_at < min_created_at:
                too_old_count += 1
            else:
                keypair_obj_or_none.decryption_authorized_at = now  # Might renew existing authorization
                keypair_obj_or_none.save()
                success_count += 1

        response_message = f"Authorization provided to {success_count} key pairs for {DECRYPTION_AUTHORIZATION_LIFESPAN_H}h, rejected for {too_old_count} key pairs due to age, and impossible for {not_found_count} key pairs not found"

        return dict(response_message=response_message,
                    success_count=success_count,
                    too_old_count=too_old_count,
                    not_found_count=not_found_count)


SQL_ESCROW_API = SqlEscrowApi(key_storage=SqlKeyStorage())
