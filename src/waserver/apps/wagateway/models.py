from django.contrib.auth.hashers import make_password, check_password, is_password_usable
from django.db import models
from django.utils.translation import ugettext_lazy as _
from django_changeset.models import CreatedModifiedByMixin
from django_cryptography.fields import encrypt

from wacryptolib.utilities import generate_uuid0


class PublicAuthenticator(CreatedModifiedByMixin):
    """
    Published mirror of an authenticator device owned by a Key Guardian.
    Username is set as the authenticator's UUID.

    Only public information is stored here, of course.
    """

    # class Meta:
    # verbose_name = _("public authenticator")
    # verbose_name_plural = _("public authenticators")
    # unique_together = [("keychain_uid", "key_algo")]

    keystore_uid = models.UUIDField(_("Keystore uid"), unique=True)

    keystore_owner = models.CharField(_("Keystore owner"), max_length=100)

    keystore_secret_hash = models.CharField(_("Keystore secret hash"), max_length=100)

    def __str__(self):
        return self.keystore_owner or str(self.pk)

    # API mimicking AbstractBaseUser password management

    def set_keystore_secret(self, keystore_secret):
        self.keystore_secret_hash = make_password(keystore_secret)

    def check_keystore_secret(self, keystore_secret):
        """
        Return a boolean of whether the keystore_secret was correct.
        Handles hashing formats behind the scenes.
        """
        return check_password(keystore_secret, self.keystore_secret_hash, setter=None)

    def set_unusable_keystore_secret(self):
        # Set a value that will never be a valid hash
        self.keystore_secret_hash = make_password(None)

    def has_usable_keystore_secret(self):
        """
        Return False if set_unusable_keystore_secret() has been called for this user.
        """
        return is_password_usable(self.keystore_secret_hash)


class PublicAuthenticatorKey(CreatedModifiedByMixin):

    public_authenticator = models.ForeignKey(PublicAuthenticator, related_name="public_keys", on_delete=models.CASCADE)

    keychain_uid = models.UUIDField(_("Keychain uid"), null=True)
    key_algo = models.CharField(_("Key algo"), max_length=20)
    key_value = encrypt(models.BinaryField(_("Public key (PEM format)")))


class RevelationRequestStatus(models.TextChoices):
    REJECTED = "REJECTED", _("REJECTED")
    ACCEPTED = "ACCEPTED", _("ACCEPTED")
    PENDING = "PENDING", _("PENDING")


class RevelationRequest(CreatedModifiedByMixin):

    target_public_authenticator = models.ForeignKey(
        PublicAuthenticator, related_name="revelation_request", on_delete=models.CASCADE
    )

    revelation_request_status = models.CharField(
        max_length=20, choices=RevelationRequestStatus.choices, default=RevelationRequestStatus.PENDING
    )
    revelation_request_uid = models.UUIDField(_("Revelation request uid"), default=generate_uuid0, unique=True)
    revelation_requestor_uid = models.UUIDField(_("Revelation requestor uid"), db_index=True)
    revelation_request_description = models.TextField(_("Revelation request description"), blank=True)
    revelation_response_public_key = encrypt(
        models.BinaryField(_("Revelation response Public key "))
    )  # For now always RSA
    revelation_response_keychain_uid = models.UUIDField(_("Revelation response keychain uid"), null=True)
    revelation_response_key_algo = models.CharField(_("Revelation response Key algo"), max_length=20)

    def __str__(self):
        return str(self.revelation_request_uid)


class SymkeyDecryptionStatus(models.TextChoices):
    DECRYPTED = "DECRYPTED", _("DECRYPTED")
    PRIVATE_KEY_MISSING = "PRIVATE_KEY_MISSING", _("PRIVATE KEY MISSING")
    CORRUPTED = "CORRUPTED", _("CORRUPTED")
    METADATA_MISMATCH = "METADATA_MISMATCH", _("METADATA_MISMATCH")
    PENDING = "PENDING", _("PENDING")


class SymkeyDecryptionRequest(CreatedModifiedByMixin):
    class Meta:
        unique_together = [("revelation_request", "symkey_decryption_request_data")]  # Fernet encryption makes this little useful

    revelation_request = models.ForeignKey(
        RevelationRequest, related_name="symkey_decryption_requests", on_delete=models.CASCADE
    )
    target_public_authenticator_key = models.ForeignKey(
        PublicAuthenticatorKey, related_name="symkey_decryption_requests", on_delete=models.CASCADE
    )
    cryptainer_name = models.CharField(
        _("Cryptainer name"), max_length=100, choices=SymkeyDecryptionStatus.choices, default=SymkeyDecryptionStatus.PENDING
        )
    cryptainer_uid = models.UUIDField(_("Cryptainer uid"), null=True)
    cryptainer_metadata = models.JSONField(_("Cryptainer metadata)"), default=dict, null=True, blank=True)
    symkey_decryption_request_data = encrypt(
        models.BinaryField(_("Symkey Request data (symkey/shard encrypted by target authenticator)"))
    )
    symkey_decryption_response_data = encrypt(
        models.BinaryField(_("Symkey Response data (symkey/shard encrypted by response public key)"), default=b"")
    )
    symkey_decryption_status = models.CharField(
        max_length=20, choices=SymkeyDecryptionStatus.choices, default=SymkeyDecryptionStatus.PENDING
    )

    def save(self, *args, **kwargs):
        # Check coherence of data tree
        assert (
            self.target_public_authenticator_key.public_authenticator
            == self.revelation_request.target_public_authenticator
        ), self.revelation_request
        return super().save()
