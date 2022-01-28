from django.contrib import admin

from .models import PublicAuthenticator, AuthenticatorPublicKey


admin.site.register(PublicAuthenticator)
admin.site.register(AuthenticatorPublicKey)
