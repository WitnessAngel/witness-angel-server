# Generated by Django 2.2.26 on 2022-01-28 22:34

from django.db import migrations, models
import django_cryptography.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="TrusteeKeypair",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True, verbose_name="Creation of record")),
                ("attached_at", models.DateTimeField(null=True, verbose_name="Attachment of free key to keychain uid")),
                ("keychain_uid", models.UUIDField(null=True, verbose_name="Keychain uid")),
                ("key_algo", models.CharField(max_length=20, verbose_name="Key type")),
                (
                    "public_key",
                    django_cryptography.fields.encrypt(models.BinaryField(verbose_name="Public key (PEM format)")),
                ),
                (
                    "private_key",
                    django_cryptography.fields.encrypt(
                        models.BinaryField(null=True, verbose_name="Private key (PEM format)")
                    ),
                ),
                ("decryption_authorized_at", models.DateTimeField(blank=True, null=True)),
            ],
            options={
                "verbose_name": "trustee key pair",
                "verbose_name_plural": "trustee key pairs",
                "unique_together": {("keychain_uid", "key_algo")},
            },
        )
    ]
