from django.contrib import admin
from .models import Order,CustomUser,FoodItem

# Register your models here.


admin.site.register(CustomUser)
admin.site.register(Order)
admin.site.register(FoodItem)