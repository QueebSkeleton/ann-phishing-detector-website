from django.contrib import admin

from .models import KnownBrand

@admin.register(KnownBrand)
class KnownBrandModelAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)
