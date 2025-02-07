#recommendations.py

from .models import FoodItem

def get_recommendations(user):
    # Example: Return the latest 5 available food items as recommendations
    return FoodItem.objects.filter(availability=True).order_by('-id')[:5]
