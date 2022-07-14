# Generated by Django 3.2.13 on 2022-07-14 21:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('wagateway', '0011_alter_symkeydecryptionrequest_symkey_decryption_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='symkeydecryptionrequest',
            name='cryptainer_name',
            field=models.CharField(choices=[('DECRYPTED', 'DECRYPTED'), ('PRIVATE_KEY_MISSING', 'PRIVATE KEY MISSING'), ('CORRUPTED', 'CORRUPTED'), ('METADATA_MISMATCH', 'METADATA_MISMATCH'), ('PENDING', 'PENDING')], default='PENDING', max_length=100, verbose_name='Cryptainer name'),
        ),
        migrations.AlterField(
            model_name='publicauthenticator',
            name='keystore_secret_hash',
            field=models.CharField(max_length=100, verbose_name='Keystore secret hash'),
        ),
        migrations.AlterField(
            model_name='revelationrequest',
            name='revelation_request_status',
            field=models.CharField(choices=[('REJECTED', 'REJECTED'), ('ACCEPTED', 'ACCEPTED'), ('PENDING', 'PENDING')], default='PENDING', max_length=20),
        ),
        migrations.AlterField(
            model_name='symkeydecryptionrequest',
            name='cryptainer_metadata',
            field=models.JSONField(blank=True, default=dict, null=True, verbose_name='Cryptainer metadata)'),
        ),
        migrations.AlterField(
            model_name='symkeydecryptionrequest',
            name='symkey_decryption_status',
            field=models.CharField(choices=[('DECRYPTED', 'DECRYPTED'), ('PRIVATE_KEY_MISSING', 'PRIVATE KEY MISSING'), ('CORRUPTED', 'CORRUPTED'), ('METADATA_MISMATCH', 'METADATA_MISMATCH'), ('PENDING', 'PENDING')], default='PENDING', max_length=20),
        ),
    ]
