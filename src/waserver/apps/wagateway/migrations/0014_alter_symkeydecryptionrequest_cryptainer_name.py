# Generated by Django 3.2.15 on 2022-09-14 14:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('wagateway', '0013_auto_20220727_0348'),
    ]

    operations = [
        migrations.AlterField(
            model_name='symkeydecryptionrequest',
            name='cryptainer_name',
            field=models.CharField(max_length=100, verbose_name='Cryptainer name'),
        ),
    ]