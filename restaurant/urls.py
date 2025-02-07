#urls.py


# from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
# from django.urls import path, include
# from rest_framework.routers import DefaultRouter
# from .views import register, user_profile, FoodItemViewSet, OrderViewSet, recommendations

# router = DefaultRouter()
# router.register(r'food-items', FoodItemViewSet)
# router.register(r'orders', OrderViewSet)

# urlpatterns = [
#     path('api/register/', register, name='register'),
#     path('api/users/me/', user_profile, name='user-profile'),
#     path('api/recommendations/', recommendations, name='recommendations'),
#     path('api/', include(router.urls)),
#     path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
#     path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
# ]

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from .views import register, login_view, user_profile,logout_view, FoodItemViewSet, OrderViewSet, recommendations
router = DefaultRouter()
router.register(r'food-items', FoodItemViewSet)
router.register(r'orders', OrderViewSet)

urlpatterns = [
    path('api/register/', register, name='register'),
    path('api/login/', login_view, name='login'),
    path('api/logout/', logout_view, name='logout'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/users/me/', user_profile, name='user-profile'),
    path('api/', include(router.urls)),
    path('api/recommendations/', recommendations, name='recommendations'),
]

