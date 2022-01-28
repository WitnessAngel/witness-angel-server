from django.contrib import admin

from .models import TrusteeKeypair


class TrusteeKeypairAdmin(admin.ModelAdmin):

    list_display = (
        "created_at",
        "keychain_uid",
        "key_algo",
        "decryption_authorized_at",
    )

    ordering = ["-id"]

    readonly_fields = ("created_at",)


admin.site.register(TrusteeKeypair, TrusteeKeypairAdmin)
