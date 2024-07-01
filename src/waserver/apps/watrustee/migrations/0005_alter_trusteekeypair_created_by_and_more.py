# Generated by Django 4.2.11 on 2024-03-30 19:23

from django.conf import settings
from django.db import migrations
import django.db.models.deletion
import django_userforeignkey.models.fields


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("watrustee", "0004_auto_20220201_1126"),
    ]

    operations = [
        migrations.AlterField(
            model_name="trusteekeypair",
            name="created_by",
            field=django_userforeignkey.models.fields.UserForeignKey(
                blank=True,
                editable=False,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="%(class)s_created",
                to=settings.AUTH_USER_MODEL,
                verbose_name="User that created this element",
            ),
        ),
        migrations.AlterField(
            model_name="trusteekeypair",
            name="last_modified_by",
            field=django_userforeignkey.models.fields.UserForeignKey(
                blank=True,
                editable=False,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="%(class)s_modified",
                to=settings.AUTH_USER_MODEL,
                verbose_name="User that last modified this element",
            ),
        ),
    ]
