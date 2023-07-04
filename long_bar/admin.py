from django.contrib import admin

from .models import KnownBrand, PhishingHint, SuspiciousTLD


@admin.register(KnownBrand)
class KnownBrandModelAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)


@admin.register(PhishingHint)
class PhishingHintModelAdmin(admin.ModelAdmin):
    list_display = ('value',)
    search_fields = ('value',)


@admin.register(SuspiciousTLD)
class SuspiciousTLDModelAdmin(admin.ModelAdmin):
    list_display = ('value',)
    search_fields = ('value',)
