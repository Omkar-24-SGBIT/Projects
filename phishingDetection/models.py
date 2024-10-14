from django.db import models


class WebsiteCheck(models.Model):
    url = models.URLField(max_length=200)
    is_legitimate = models.BooleanField()
    message = models.CharField(max_length=200)

    def __str__(self):
        return self.url
