# Generated by Django 2.2.6 on 2019-11-10 22:38

from django.db import migrations, models
import django_cryptography.fields


class Migration(migrations.Migration):

    dependencies = [
        ('waescrow', '0005_auto_20190918_1245'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='escrowkeypair',
            name='keypair',
        ),
        migrations.AddField(
            model_name='escrowkeypair',
            name='private_key',
            field=django_cryptography.fields.encrypt(models.TextField(default=b'', verbose_name='Private key (PEM format)')),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='escrowkeypair',
            name='public_key',
            field=django_cryptography.fields.encrypt(models.TextField(default=b'', verbose_name='Public key (PEM format)')),
            preserve_default=False,
        ),
    ]
