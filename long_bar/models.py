from django.db import models


class KnownBrand(models.Model):
    name = models.CharField(max_length=255, unique=True)


class PhishingHint(models.Model):
    value = models.CharField(max_length=255, unique=True)


class SuspiciousTLD(models.Model):
    value = models.CharField(max_length=255, unique=True)
