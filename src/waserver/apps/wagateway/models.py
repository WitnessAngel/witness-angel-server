
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password, check_password, is_password_usable
from django.db import models
from django.utils.translation import ugettext_lazy as _
from django_cryptography.fields import encrypt


class PublicAuthenticator(models.Model):
    """
    Published mirror of an authenticator device owned by a Key Guardian.
    Username is set as the authenticator's UUID.

    Only public information is stored here, of course.
    """

    class Meta:
        verbose_name = _("authenticator user")
        verbose_name_plural = _("authenticator users")
        # unique_together = [("keychain_uid", "key_algo")]

    keystore_uid = models.UUIDField(_("Keystore uid"), unique=True)

    keystore_owner = models.CharField(_("Keystore owner"), max_length=100)

    keystore_secret = models.CharField(_('Keystore secret'), max_length=128)

    # Todo add real mobile_phone field later!
    # username = models.UUIDField(_("keychain uid"), default=uuid.uuid4, null=True)

    #: Hash of the secret string of the authenticator
    # authenticator_secret = models.CharField(_('authenticator secret'), max_length=128)

    # API mimicking AbstractBaseUser password management
    def set_keystore_secret(self, keystore_secret):
        self.keystore_secret = make_password(keystore_secret)

    def check_keystore_secret(self, keystore_secret):
        """
        Return a boolean of whether the keystore_secret was correct. Handles
        hashing formats behind the scenes.
        """

        def setter(keystore_secret):
            self.set_password(keystore_secret)
            # Password hash upgrades shouldn't be considered password changes.
            self.save(update_fields=["keystore_secret"])

        return check_password(keystore_secret, self.keystore_secret, setter)

    def set_unusable_keystore_secret(self):
        # Set a value that will never be a valid hash
        self.keystore_secret = make_password(None)

    def has_usable_keystore_secret(self):
        """
        Return False if set_unusable_keystore_secret() has been called for this user.
        """
        return is_password_usable(self.keystore_secret)


def authenticate_authenticator_user(username, password, authenticathor_secret):
    user = authenticate(username=username, password=password)
    if not user:
        raise ValueError("bad credentials")  # FIXME use custom exceptions!
    if not user.check_authenticator_secret(authenticathor_secret):
        raise ValueError("bad authenticator secret")  # FIXME use custom exceptions!
    return user


class AuthenticatorPublicKey(models.Model):
    # authenticator_user = models.ForeignKey(AuthenticatorUser, on_delete=models.CASCADE, verbose_name=_(
    # 'authenticator user'))

    authenticator_user = models.ForeignKey(PublicAuthenticator, related_name='public_keys',
                                           on_delete=models.CASCADE)

    active = models.BooleanField(_("active"), default=True)  # If this public key might be used for new containers
    keychain_uid = models.UUIDField(_("Keychain uid"), null=True)
    key_algo = models.CharField(_("Key type"), max_length=20)
    payload = encrypt(models.BinaryField(_("Public key (PEM format)")))

