#serializers.py

from rest_framework import serializers
from .models import CustomUser, FoodItem, Order

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password', 'is_customer', 'is_admin','profile_image')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = CustomUser.objects.create_user(**validated_data)
        return user

class FoodItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = FoodItem
        fields = '__all__'

# class OrderSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Order
#         fields = '__all__'



class OrderSerializer(serializers.ModelSerializer):
    # Calculate total_price using a SerializerMethodField
    total_price = serializers.SerializerMethodField()
    customer = serializers.PrimaryKeyRelatedField(read_only=True)  # Automatically set customer
    status = serializers.CharField(default='pending')  # Default value for status

    class Meta:
        model = Order
        fields = ['id', 'items', 'total_price', 'status', 'customer']  # Include total_price, status, and customer

    def get_total_price(self, obj):
        """Calculate total price of the order from its items."""
        return sum(item.price for item in obj.items.all())  # Calculate total price based on items associated with the order

    def create(self, validated_data):
        """Override the create method to automatically handle total_price, status, and customer"""
        items = validated_data.get('items')

        # Calculate total price based on the items
        total_price = sum(item.price for item in items)

        # Create the order instance with the validated data
        order = Order.objects.create(
            customer=self.context['request'].user,  # Automatically set the customer from the request
            total_price=total_price,
            status='pending'  # Default status is 'pending'
        )

        # Associate the items with the order
        order.items.set(items)
        order.save()  # Save the order with its items and total price

        return order