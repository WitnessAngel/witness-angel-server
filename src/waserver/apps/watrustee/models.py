from django.db import models
from django.utils.translation import ugettext_lazy as _
from django_changeset.models import CreatedModifiedByMixin
from django_cryptography.fields import encrypt

DECRYPTION_AUTHORIZATION_LIFESPAN_H = 24  # Access remains only authorized for that duration


class TrusteeKeypair(CreatedModifiedByMixin):
    """
    Stores key pairs attached to UUIDs.
    Free keys are inserted with keychain_uid=None.
    """

    class Meta:
        # verbose_name = _("trustee key pair")
        # verbose_name_plural = _("trustee key pairs")
        unique_together = [("keychain_uid", "key_algo")]

    keychain_uid = models.UUIDField(_("Keychain uid"), null=True, blank=True)  # Null for free keys
    key_algo = models.CharField(_("Key type"), max_length=20)
    public_key = encrypt(models.BinaryField(_("Public key (PEM format)")))
    private_key = encrypt(models.BinaryField(_("Private key (PEM format)"), null=True))  # Might NOT exist

    # This remains null for non-pregenerated keys
    attached_at = models.DateTimeField(_("Attachment of free key to keychain uid"), null=True, blank=True)

    # When set, the private key can be accessed for DECRYPTION_AUTHORIZATION_LIFESPAN_H hours after this datetime
    decryption_authorized_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return "TrusteeKeypair (type=%s, uid=%s)" % (self.key_algo, self.keychain_uid)
