
from rest_framework import serializers

from waescrow.models import AuthenticatorUser


class AuthenticatorUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = AuthenticatorUser
        fields = ['description', 'authenticator_secret']

