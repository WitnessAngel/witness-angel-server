import threading
import uuid
from datetime import timedelta

from django.utils import timezone
from wacryptolib.utilities import synchronized

from wacryptolib.escrow import KeyStorageBase, EscrowApi
from waescrow.models import EscrowKeypair, DECRYPTION_AUTHORIZATION_LIFESPAN_H


class SqlKeyStorage(KeyStorageBase):
    """
    Store keys in records of SQL DB.

    Since SQLITE has bad support for concurrent transactions and isolation levels, we rely on
    in-process locks to prevent lost updates, but it also means that this storage is
    NOT MULTI-PROCESS SAFE!
    """

    # TODO - ensure the secret key of Django DB storage is given by environment variable for security?

    _lock = threading.Lock()  # Process-wide lock

    def _fetch_key_object_or_none(self, keychain_uid: uuid.UUID, key_type: str) -> EscrowKeypair:
        try:
            return EscrowKeypair.objects.get(keychain_uid=keychain_uid, key_type=key_type)
        except EscrowKeypair.DoesNotExist:
            return None

    def _ensure_keypair_does_not_exist(self, keychain_uid, key_type):
        # program might still raise IntegrityError if the same key is inserted concurrently
        if self._fetch_key_object_or_none(keychain_uid=keychain_uid, key_type=key_type):
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
        keypair_obj_or_none = self._fetch_key_object_or_none(keychain_uid=keychain_uid, key_type=key_type)
        return keypair_obj_or_none.public_key if keypair_obj_or_none else None

    @synchronized
    def get_private_key(self, *, keychain_uid: uuid.UUID, key_type: str) -> bytes:
        keypair_obj_or_none = self._fetch_key_object_or_none(keychain_uid=keychain_uid, key_type=key_type)
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
        keypair_obj_or_none = EscrowKeypair.objects.filter(keychain_uid=None, key_type=key_type).first()
        if not keypair_obj_or_none:
            raise RuntimeError(
                "No free keypair of type %s available in sql storage" % key_type
            )
        keypair_obj_or_none.keychain_uid = keychain_uid
        keypair_obj_or_none.save()


class SqlEscrowApi(EscrowApi):
    def decrypt_with_private_key(self,
            keychain_uid,
            key_type,
            encryption_algo,
            cipherdict):

        # TODO - a redesign of the API could prevent the double DB lookup here, but not sure if it's useful on the long term...
        keypair_obj = EscrowKeypair.objects.get(keychain_uid=keychain_uid, key_type=key_type)

        decryption_authorized_at = keypair_obj.decryption_authorized_at

        if not decryption_authorized_at:
            raise RuntimeError("Decryption not authorized")  # TODO better exception class

        now = timezone.now()
        if not (decryption_authorized_at < now < decryption_authorized_at + timedelta(hours=DECRYPTION_AUTHORIZATION_LIFESPAN_H)):
            raise RuntimeError("Decryption authorization is not currently active")  # TODO better exception class

        return super().decrypt_with_private_key(keychain_uid=keychain_uid, key_type=key_type,encryption_algo=encryption_algo, cipherdict=cipherdict)


SQL_ESCROW_API = SqlEscrowApi(key_storage=SqlKeyStorage())
