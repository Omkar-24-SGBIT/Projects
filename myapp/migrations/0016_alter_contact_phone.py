# Generated by Django 5.0.3 on 2024-04-13 08:51

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("myapp", "0015_contact_phone"),
    ]

    operations = [
        migrations.AlterField(
            model_name="contact",
            name="phone",
            field=models.CharField(max_length=10, null=True),
        ),
    ]
