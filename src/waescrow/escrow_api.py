import uuid
from datetime import timedelta

from django.utils import timezone

from wacryptolib.escrow import KeyStorageBase, EscrowApi
from waescrow.models import EscrowKeypair, DECRYPTION_AUTHORIZATION_LIFESPAN_H


class SqlKeyStorage(KeyStorageBase):

    # TODO - ensure the secret key of Django DB storage is given by environment variable for security?

    def set_keys(self, *, keychain_uid: uuid.UUID, key_type: str, public_key: bytes, private_key: bytes):
        # Raises IntegrityError if this ID already exists
        EscrowKeypair.objects.create(keychain_uid=keychain_uid, key_type=key_type.upper(),
                                     public_key=public_key, private_key=private_key)

    def _fetch_key_object_or_none(self, keychain_uid: uuid.UUID, key_type: str) -> EscrowKeypair:
        try:
            return EscrowKeypair.objects.get(keychain_uid=keychain_uid, key_type=key_type)
        except EscrowKeypair.DoesNotExist:
            return None

    def get_public_key(self, *, keychain_uid: uuid.UUID, key_type: str) -> bytes:
        keypair_obj_or_none = self._fetch_key_object_or_none(keychain_uid=keychain_uid, key_type=key_type)
        return keypair_obj_or_none.public_key if keypair_obj_or_none else None

    def get_private_key(self, *, keychain_uid: uuid.UUID, key_type: str) -> bytes:
        keypair_obj_or_none = self._fetch_key_object_or_none(keychain_uid=keychain_uid, key_type=key_type)
        return keypair_obj_or_none.private_key if keypair_obj_or_none else None


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
