from django.db import models

class KnownBrand(models.Model):
    name = models.CharField(max_length=255)
