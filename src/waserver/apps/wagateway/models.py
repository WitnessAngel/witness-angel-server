from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password, check_password, is_password_usable
from django.db import models
from django.utils.translation import ugettext_lazy as _
from django_cryptography.fields import encrypt
from django_changeset.models import CreatedModifiedByMixin
from rest_framework.fields import JSONField
from wacryptolib.utilities import generate_uuid0


class PublicAuthenticator(CreatedModifiedByMixin):
    """
    Published mirror of an authenticator device owned by a Key Guardian.
    Username is set as the authenticator's UUID.

    Only public information is stored here, of course.
    """

    #class Meta:
        #verbose_name = _("public authenticator")
        #verbose_name_plural = _("public authenticators")
        # unique_together = [("keychain_uid", "key_algo")]

    keystore_uid = models.UUIDField(_("Keystore uid"), unique=True)

    keystore_owner = models.CharField(_("Keystore owner"), max_length=100)

    keystore_secret_hash = models.CharField(_('Keystore secret hash'), max_length=128)

    def __str__(self):
        return self.keystore_owner or self.pk

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


# TODO : rename to PublicAuthenticatorKey ?
class AuthenticatorPublicKey(CreatedModifiedByMixin):
    # authenticator_user = models.ForeignKey(AuthenticatorUser, on_delete=models.CASCADE, verbose_name=_(
    # 'authenticator user'))

    authenticator_user = models.ForeignKey(PublicAuthenticator, related_name='public_keys', on_delete=models.CASCADE)

    keychain_uid = models.UUIDField(_("Keychain uid"), null=True)
    key_algo = models.CharField(_("Key algo"), max_length=20)
    key_value = encrypt(models.BinaryField(_("Public key (PEM format)")))


class RequestStatus(models.TextChoices):
    REJECTED = 'REJECTED', _('REJECTED')
    ACCEPTED = 'ACCEPTED', _('ACCEPTED')
    PENDING = 'PENDING', _('PENDING')


# TODO : rename to RevelationRequest ?
class DecryptionRequest(CreatedModifiedByMixin):

    # FIXME rename to target_public_authenticator ?
    public_authenticator = models.ForeignKey(PublicAuthenticator, related_name='decryption_request', on_delete=models.CASCADE)

    # FIXME prefiex all fields by revelation_xxx, to diféfrentiate from fields of SymkeyDecryptionRequest?
    request_status = models.CharField(max_length=128, choices=RequestStatus.choices, default=RequestStatus.PENDING)
    # FIXME : make this one UNIQUE
    decryption_request_uid = models.UUIDField(_("Decryption request uid"), default=generate_uuid0)  # FIXME rename to request_uid ?
    requester_uid = models.UUIDField(_("Requester uid"), db_index=True)
    description = models.TextField(_("Description"), blank=True)  # FIXME rename to request_description ??
    response_public_key = encrypt(models.BinaryField(_("Response Public key ")))  # For now always RSA
    response_keychain_uid = models.UUIDField(_("Response keychain uid"), null=True)
    response_key_algo = models.CharField(_("Response Key algo"), max_length=20)



class DecryptionStatus(models.TextChoices):
    DECRYPTED = 'DECRYPTED', _('DECRYPTED')
    PRIVATE_KEY_MISSING = 'PRIVATE KEY MISSING', _('PRIVATE KEY MISSING')
    CORRUPTED = 'CORRUPTED', _('CORRUPTED')
    MISMATCH = 'MISMATCH', _('MISMATCH')  # METADATA MISMATCH
    PENDING = 'PENDING', _('PENDING')


# TODO : rename to SymkeyDecryptionRequest (and rename decryption_request too) ?
class SymkeyDecryption(CreatedModifiedByMixin):

    decryption_request = models.ForeignKey(DecryptionRequest, related_name='symkeys_decryption', on_delete=models.CASCADE)
    authenticator_public_key = models.ForeignKey(AuthenticatorPublicKey, related_name='symkeys_decryption', on_delete=models.CASCADE)  # FIXME check integrity of relation loop
    cryptainer_uid = models.UUIDField(_("Cryptainer uid"), null=True)
    cryptainer_metadata = models.JSONField(_("Cryptainer metadata)"), default=dict, null=True)
    request_data = encrypt(models.BinaryField(_("Request data (symkey/shard encrypted by target authenticator)")))
    response_data = encrypt(models.BinaryField(_("Response data (symkey/shard encrypted by response public key)"), default=b''))
    decryption_status = models.CharField(max_length=128, choices=DecryptionStatus.choices, default=DecryptionStatus.PENDING)
    unique_together = ('decryption_request', 'request_data',)  # FIXME what is that? It shall be tested, and in Meta class
