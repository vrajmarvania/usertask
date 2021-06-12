from django.contrib import admin

# Register your models here.
from .models import Address

@admin.register(Address)
class Address(admin.ModelAdmin):
    class Meta:
        model = Address
        list_display=['__all__']