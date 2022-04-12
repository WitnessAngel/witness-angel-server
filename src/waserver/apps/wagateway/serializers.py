from rest_framework import serializers
from rest_framework.fields import UUIDField, Field

# from watrustee.models import AuthenticatorUser, AuthenticatorPublicKey

from waserver.apps.wagateway.models import PublicAuthenticator, AuthenticatorPublicKey, DecryptionRequest, \
    SymkeyDecryption


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
    key_value = BinaryField()
    # symkeys_decryption = SymkeyDecryptionSerializer(many=True, read_only=True)

    class Meta:
        model = AuthenticatorPublicKey
        fields = ['keychain_uid', 'key_algo', 'key_value']


class PublicAuthenticatorSerializer(serializers.ModelSerializer):
    keystore_uid = TransparentRepresentationUUIDField()
    public_keys = AuthenticatorPublicKeySerializer(many=True, read_only=True)
    # decryption_request = DecryptionRequestSerializer(many=True, read_only=True)

    class Meta:
        model = PublicAuthenticator
        fields = ['keystore_owner', 'keystore_uid', 'public_keys']


class SymkeyDecryptionSerializer(serializers.ModelSerializer):
    cryptainer_uid = TransparentRepresentationUUIDField()
    request_data = BinaryField()
    response_data = BinaryField()
    authenticator_public_key = AuthenticatorPublicKeySerializer(read_only=True)

    class Meta:
        model = SymkeyDecryption
        fields = ['authenticator_public_key', 'cryptainer_uid', 'cryptainer_metadata', 'request_data', 'response_data', 'decryption_status']


class DecryptionRequestSerializer(serializers.ModelSerializer):
    requester_uid = TransparentRepresentationUUIDField()
    response_public_key = BinaryField()
    symkeys_decryption = SymkeyDecryptionSerializer(many=True, read_only=True)
    public_authenticator = PublicAuthenticatorSerializer(read_only=True)

    class Meta:
        model = DecryptionRequest
        fields = ['public_authenticator', 'decryption_request_uid', 'requester_uid', 'description', 'response_public_key', 'request_status',
                  'symkeys_decryption']



