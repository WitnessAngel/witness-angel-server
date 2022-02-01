from django.contrib import admin
from django.db.models import Count
#from django.contrib.admin import display

from .models import PublicAuthenticator, AuthenticatorPublicKey


class AuthenticatorPublicKeyInline(admin.StackedInline):
    model = AuthenticatorPublicKey
    extra = 0
    fields = ["keychain_uid", "key_algo", "key_value_length", "created_at"]

    readonly_fields = ['key_value_length', "created_at"]

    def key_value_length(self, obj):
        return len(obj.key_value)


class PublicAuthenticatorAdmin(admin.ModelAdmin):
    list_display = ["keystore_owner", "keystore_uid", "public_key_count", "created_at"] ##, "created_at"]
    #list_filter = ['']
    #changelist_links = ['projects']
    #change_links = ["public_keys"]
    inlines = [AuthenticatorPublicKeyInline]
    readonly_fields = ["created_at"]
    ordering = ["-pk"]

    #@display(description='Public keys')
    def public_key_count(self, obj):
        return obj.public_key_count

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        queryset = queryset.annotate(public_key_count=Count("public_keys"))
        return queryset


admin.site.register(PublicAuthenticator, PublicAuthenticatorAdmin)
#admin.site.register(AuthenticatorPublicKey)  # Not needed


