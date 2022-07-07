from django.contrib import admin

from .models import TrusteeKeypair


class TrusteeKeypairAdmin(admin.ModelAdmin):

    list_display = (
        "keychain_uid",
        "key_algo",
        "decryption_authorized_at",
        "public_key_length",
        "private_key_length",
        "created_at",
    )

    ordering = ["-pk"]

    readonly_fields = ("public_key_length", "private_key_length", "created_at")

    def public_key_length(self, obj):
        return len(obj.public_key)

    def private_key_length(self, obj):
        return len(obj.private_key) if obj.private_key is not None else None


admin.site.register(TrusteeKeypair, TrusteeKeypairAdmin)
