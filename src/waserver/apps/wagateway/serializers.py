# This file is part of Witness Angel Server
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import datetime

from rest_framework import serializers
from rest_framework.fields import UUIDField, Field, DateTimeField

from waserver.apps.wagateway.models import (
    PublicAuthenticator,
    PublicAuthenticatorKey,
    RevelationRequest,
    SymkeyDecryptionRequest,
)


class BinaryField(Field):
    def run_validation(self, data):
        if not isinstance(data, bytes):
            self.fail("Unsupported data type in BinaryField: %s" % type(data))
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


class TransparentRepresentationDatetimeField(DateTimeField):
    def enforce_timezone(self, value):
        return value

    def default_timezone(self):
        return None

    def to_internal_value(self, value):
        if isinstance(value, datetime.date) and not isinstance(value, datetime.datetime):
            self.fail('date')

        if isinstance(value, datetime.datetime):
            return value

        self.fail('invalid')

    def to_representation(self, value):
        return value


class PublicAuthenticatorKeySerializer(serializers.ModelSerializer):
    keychain_uid = TransparentRepresentationUUIDField()
    key_value = BinaryField()

    class Meta:
        model = PublicAuthenticatorKey
        fields = ["keychain_uid", "key_algo", "key_value"]


class PublicAuthenticatorSerializer(serializers.ModelSerializer):
    keystore_uid = TransparentRepresentationUUIDField()
    public_keys = PublicAuthenticatorKeySerializer(many=True, read_only=True)
    keystore_creation_datetime = TransparentRepresentationDatetimeField()
    # decryption_request = DecryptionRequestSerializer(many=True, read_only=True)

    class Meta:
        model = PublicAuthenticator
        fields = ["keystore_uid", "keystore_owner", "keystore_creation_datetime", "public_keys"]


class SymkeyDecryptionRequestSerializer(serializers.ModelSerializer):
    cryptainer_uid = TransparentRepresentationUUIDField()
    symkey_decryption_request_data = BinaryField()
    symkey_decryption_response_data = BinaryField()
    target_public_authenticator_key = PublicAuthenticatorKeySerializer(read_only=True)

    class Meta:
        model = SymkeyDecryptionRequest
        fields = [
            "target_public_authenticator_key",
            "cryptainer_name",
            "cryptainer_uid",
            "cryptainer_metadata",
            "symkey_decryption_request_data",
            "symkey_decryption_response_data",
            "symkey_decryption_status",
        ]


class RevelationRequestSerializer(serializers.ModelSerializer):
    revelation_requestor_uid = TransparentRepresentationUUIDField()
    revelation_request_uid = TransparentRepresentationUUIDField()
    revelation_response_keychain_uid = TransparentRepresentationUUIDField()
    revelation_response_public_key = BinaryField()
    symkey_decryption_requests = SymkeyDecryptionRequestSerializer(many=True, read_only=True)
    target_public_authenticator = PublicAuthenticatorSerializer(read_only=True)
    created_at = TransparentRepresentationDatetimeField()

    class Meta:
        model = RevelationRequest
        fields = [
            "target_public_authenticator",
            "revelation_request_uid",
            "revelation_requestor_uid",
            "revelation_request_description",
            "revelation_response_public_key",
            "revelation_response_keychain_uid",
            "revelation_response_key_algo",
            "revelation_request_status",
            "symkey_decryption_requests",
            "created_at",
        ]
