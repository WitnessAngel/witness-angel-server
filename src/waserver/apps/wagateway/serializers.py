from rest_framework import serializers
from rest_framework.fields import UUIDField, Field

from waserver.apps.wagateway.models import PublicAuthenticator, PublicAuthenticatorKey, RevelationRequest, \
    SymkeyDecryptionRequest


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


class PublicAuthenticatorKeySerializer(serializers.ModelSerializer):
    keychain_uid = TransparentRepresentationUUIDField()
    key_value = BinaryField()

    class Meta:
        model = PublicAuthenticatorKey
        fields = ['keychain_uid', 'key_algo', 'key_value']


class PublicAuthenticatorSerializer(serializers.ModelSerializer):
    keystore_uid = TransparentRepresentationUUIDField()
    public_keys = PublicAuthenticatorKeySerializer(many=True, read_only=True)
    # decryption_request = DecryptionRequestSerializer(many=True, read_only=True)

    class Meta:
        model = PublicAuthenticator
        fields = ['keystore_owner', 'keystore_uid', 'public_keys']


class SymkeyDecryptionRequestSerializer(serializers.ModelSerializer):
    cryptainer_uid = TransparentRepresentationUUIDField()
    symkey_decryption_request_data = BinaryField()
    symkey_decryption_response_data = BinaryField()
    public_authenticator_key = PublicAuthenticatorKeySerializer(read_only=True)

    class Meta:
        model = SymkeyDecryptionRequest
        fields = ['public_authenticator_key', 'cryptainer_uid', 'cryptainer_metadata', 'symkey_decryption_request_data',
                  'symkey_decryption_response_data', 'symkey_decryption_status']


class RevelationRequestSerializer(serializers.ModelSerializer):
    requester_uid = TransparentRepresentationUUIDField()
    revelation_request_uid = TransparentRepresentationUUIDField()
    revelation_response_keychain_uid = TransparentRepresentationUUIDField()
    revelation_response_public_key = BinaryField()
    symkey_decryption_requests = SymkeyDecryptionRequestSerializer(many=True, read_only=True)
    target_public_authenticator = PublicAuthenticatorSerializer(read_only=True)

    class Meta:
        model = RevelationRequest
        fields = ['target_public_authenticator', 'revelation_request_uid', 'requester_uid',
                  'revelation_request_description', 'revelation_response_public_key',
                  'revelation_response_keychain_uid', 'revelation_response_key_algo',
                  'revelation_request_status', 'symkey_decryption_requests']



