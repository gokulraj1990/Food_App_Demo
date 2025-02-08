#models.py

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import make_password


# Custom user model
class CustomUser(AbstractUser):
    is_customer = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    profile_image = models.ImageField(upload_to='profile_images/', null=True, blank=True)

    def save(self, *args, **kwargs):
        # Ensure the password is hashed before saving if it's set
        if self.password and not self.password.startswith('pbkdf2_sha256$'):
            self.password = make_password(self.password)  # Hash the password

        super().save(*args, **kwargs)

    def __str__(self):
        return self.username

# Food Item model
class FoodItem(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(null=True, blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    category = models.CharField(max_length=50)
    availability = models.BooleanField(default=True)
    image = models.ImageField(upload_to='food_images/',null=True, blank=True)

    def __str__(self):
        return self.name

# Order model
class Order(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]
    customer = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    items = models.ManyToManyField(FoodItem)
    total_price = models.DecimalField(max_digits=10, decimal_places=2, blank=True)
    status = models.CharField(choices=STATUS_CHOICES, default='pending', max_length=20)

    def save(self, *args, **kwargs):
        """ Override save to first create order, then calculate total_price """
        super().save(*args, **kwargs)  # Save order first
        self.total_price = sum(item.price for item in self.items.all())  # Now we can access items
        super().save(update_fields=['total_price'])  # Save updated total_price

    def __str__(self):
        return f"Order {self.id} for {self.customer.username}"