import base64
from rest_framework import serializers
from rest_framework.fields import UUIDField, Field

# from watrustee.models import AuthenticatorUser, AuthenticatorPublicKey

from watrustee.models import PublicAuthenticator, AuthenticatorPublicKey

"""
class AuthenticatorUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = AuthenticatorUser
        fields = ['description', 'username'] """


class BinaryField(Field):
    def run_validation(self, data):
        if not isinstance(data, bytes):
            self.fail('Unsupported data type in BinaryField: %s' % type(data))  # TODO
        return super(BinaryField, self).run_validation(data)

    def to_internal_value(self, data):
        return data

    def to_representation(self, value):
        return value


class TransparentRepresentationMixin:
    def to_representation(self, value):
        return value


class TransparentRepresentationUUIDField(TransparentRepresentationMixin, UUIDField):
    pass


class AuthenticatorPublicKeySerializer(serializers.ModelSerializer):
    keychain_uid = TransparentRepresentationUUIDField()
    payload = BinaryField()

    class Meta:
        model = AuthenticatorPublicKey
        fields = ['keychain_uid', 'key_algo', 'payload']


class PublicAuthenticatorSerializer(serializers.ModelSerializer):
    keystore_uid = TransparentRepresentationUUIDField()
    public_keys = AuthenticatorPublicKeySerializer(many=True, read_only=True)

    class Meta:
        model = PublicAuthenticator
        fields = ['keystore_owner', 'keystore_uid', 'public_keys']
