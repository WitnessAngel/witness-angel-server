from rest_framework import serializers
from rest_framework.fields import UUIDField, Field

from watrustee.models import AuthenticatorUser, AuthenticatorPublicKey

"""
class AuthenticatorUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = AuthenticatorUser
        fields = ['description', 'username'] """


class BinaryField(Field):
    def run_validation(self, data):
        if not isinstance(data, bytes):
            self.fail('xx')  # TODO
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


class AuthenticatorPublicKey(serializers.ModelSerializer):
    keychain_uid = TransparentRepresentationUUIDField()
    payload = BinaryField()

    class Meta:
        model = AuthenticatorPublicKey
        fields = ['keychain_uid', 'key_algo', 'payload']


class AuthenticatorUserSerializer(serializers.ModelSerializer):
    public_keys = AuthenticatorPublicKey(many=True, read_only=True)

    class Meta:
        model = AuthenticatorUser
        fields = ['description', 'username', 'public_keys']
