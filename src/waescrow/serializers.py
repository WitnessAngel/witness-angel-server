
from rest_framework import serializers

from waescrow.models import AuthenticatorUser, AuthenticatorPublicKey

"""
class AuthenticatorUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = AuthenticatorUser
        fields = ['description', 'authenticator_secret'] """


class AuthenticatorPublicKey(serializers.ModelSerializer):
    class Meta:
        model = AuthenticatorPublicKey
        fields = ('keychain_uid', 'key_type')


class AuthenticatorUserSerializer(serializers.ModelSerializer):
    public_key = AuthenticatorPublicKey(many=True, read_only=True)

    class Meta:
        model = AuthenticatorUser
        fields = ['description',  'authenticator_secret', 'public_key']

