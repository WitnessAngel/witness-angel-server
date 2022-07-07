# Generated by Django 2.2.26 on 2022-01-30 22:35

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django_userforeignkey.models.fields


class Migration(migrations.Migration):

    dependencies = [migrations.swappable_dependency(settings.AUTH_USER_MODEL), ("watrustee", "0001_initial")]

    operations = [
        migrations.AddField(
            model_name="trusteekeypair",
            name="created_by",
            field=django_userforeignkey.models.fields.UserForeignKey(
                blank=True,
                editable=False,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="trusteekeypair_created",
                to=settings.AUTH_USER_MODEL,
                verbose_name="User that created this element",
            ),
        ),
        migrations.AddField(
            model_name="trusteekeypair",
            name="last_modified_at",
            field=models.DateTimeField(
                auto_now=True, db_index=True, null=True, verbose_name="Date when this element was last modified"
            ),
        ),
        migrations.AddField(
            model_name="trusteekeypair",
            name="last_modified_by",
            field=django_userforeignkey.models.fields.UserForeignKey(
                blank=True,
                editable=False,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="trusteekeypair_modified",
                to=settings.AUTH_USER_MODEL,
                verbose_name="User that last modified this element",
            ),
        ),
        migrations.AlterField(
            model_name="trusteekeypair",
            name="attached_at",
            field=models.DateTimeField(blank=True, null=True, verbose_name="Attachment of free key to keychain uid"),
        ),
    ]
