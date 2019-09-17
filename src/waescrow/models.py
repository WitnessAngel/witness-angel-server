# -*- coding: utf-8 -*-

from django.db import models
from django.utils.translation import ugettext_lazy as _
from django_cryptography.fields import encrypt




class EscrowKeypair(models.Model):

    class Meta:
        verbose_name = _("escrow key pair")
        verbose_name_plural = _("escrow key pairs")
        unique_together = [('keychain_uid', 'key_type')]

    created_at = models.DateTimeField(auto_now_add=True)

    keychain_uid = models.UUIDField(_("Keychain uid"))
    key_type = models.CharField(_("Key type"), max_length=20)
    keypair = encrypt(models.TextField(_("Key pair")))


