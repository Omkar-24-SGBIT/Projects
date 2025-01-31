# Generated by Django 5.0.3 on 2024-05-17 09:46

from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="WebsiteCheck",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("url", models.URLField()),
                ("is_legitimate", models.BooleanField()),
                ("message", models.CharField(max_length=200)),
                ("random_number", models.IntegerField()),
            ],
        ),
    ]
