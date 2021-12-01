# Generated by Django 2.2.24 on 2021-11-29 23:33

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('waescrow', '0009_auto_20211130_0025'),
    ]

    operations = [
        migrations.AlterField(
            model_name='authenticatoruser',
            name='username',
            field=models.UUIDField(default=uuid.uuid4, null=True, verbose_name='keychain uid'),
        ),
    ]
