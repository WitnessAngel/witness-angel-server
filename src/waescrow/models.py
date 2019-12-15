# -*- coding: utf-8 -*-

from django.db import models
from django.utils.translation import ugettext_lazy as _
from django_cryptography.fields import encrypt


DECRYPTION_AUTHORIZATION_LIFESPAN_H = (
    24
)  # Access remains only authorized for that duration


class EscrowKeypair(models.Model):
    """
    Stores key pairs attached to UUIDs.
    Free keys are inserted with keychain_uid=None.
    """

    class Meta:
        verbose_name = _("escrow key pair")
        verbose_name_plural = _("escrow key pairs")
        unique_together = [("keychain_uid", "key_type")]

    created_at = models.DateTimeField(auto_now_add=True)

    keychain_uid = models.UUIDField(_("Keychain uid"), null=True)
    key_type = models.CharField(_("Key type"), max_length=20)
    public_key = encrypt(models.BinaryField(_("Public key (PEM format)")))
    private_key = encrypt(models.BinaryField(_("Private key (PEM format)")))

    # When set, the private key can be accessed for DECRYPTION_AUTHORIZATION_LIFESPAN_H hours after this datetime
    decryption_authorized_at = models.DateTimeField(
        blank=True, null=True
    )  # FIXME TYPO!!!

    def __repr__(self):
        return "<EscrowKeypair (type=%s, uid=%s)>" % (self.key_type, self.keychain_uid)
