from django.contrib import admin
from django.db.models import Count

from .models import PublicAuthenticator, PublicAuthenticatorKey, SymkeyDecryptionRequest, RevelationRequest


class AuthenticatorPublicKeyInline(admin.StackedInline):
    model = PublicAuthenticatorKey
    extra = 0
    fields = ["keychain_uid", "key_algo", "key_value_length", "created_at"]

    readonly_fields = ['key_value_length', "created_at"]

    def key_value_length(self, obj):
        return len(obj.key_value)


class PublicAuthenticatorAdmin(admin.ModelAdmin):
    list_display = ["keystore_owner", "keystore_uid", "public_key_count", "created_at"]
    inlines = [AuthenticatorPublicKeyInline]
    readonly_fields = ["created_at"]
    ordering = ["-pk"]

    def public_key_count(self, obj):
        return obj.public_key_count

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        queryset = queryset.annotate(public_key_count=Count("public_keys"))
        return queryset


class SymkeyDecryptionRequestInline(admin.StackedInline):
    model = SymkeyDecryptionRequest
    extra = 0
    fields = ["target_public_authenticator_key", "cryptainer_uid", "cryptainer_metadata", "symkey_decryption_status",
              "symkey_decryption_request_data_length", "symkey_decryption_response_data_length"]

    readonly_fields = ["symkey_decryption_request_data_length", "symkey_decryption_response_data_length", "created_at"]

    def symkey_decryption_request_data_length(self, obj):
        return len(obj.symkey_decryption_request_data)

    def symkey_decryption_response_data_length(self, obj):
        return len(obj.symkey_decryption_response_data)


class RevelationRequestAdmin(admin.ModelAdmin):
    list_display = ["revelation_request_uid", "target_public_authenticator", "revelation_request_status", "symkey_decryption_request_count", "created_at"]
    inlines = [SymkeyDecryptionRequestInline]
    readonly_fields = ["created_at"]
    ordering = ["-pk"]

    def symkey_decryption_request_count(self, obj):
        return obj.symkey_decryption_requests

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        queryset = queryset.annotate(public_key_count=Count("symkey_decryption_requests"))
        return queryset


admin.site.register(PublicAuthenticator, PublicAuthenticatorAdmin)

admin.site.register(RevelationRequest, RevelationRequestAdmin)


