from django.contrib.auth import authenticate
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated, IsAdminUser,AllowAny
from rest_framework.decorators import api_view, permission_classes, authentication_classes, parser_classes
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import filters
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.http import JsonResponse
from django.conf import settings
from django.core.mail import send_mail
from .models import CustomUser, FoodItem, Order
from .serializers import UserSerializer, FoodItemSerializer, OrderSerializer
from .recommendations import get_recommendations
from .authentication import CookieJWTAuthentication  # Import custom authentication class
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError

# ✅ Register User (Customer Only)
@api_view(['POST'])
def register(request):
    try:
        data = request.data.copy()
        data['is_customer'] = True  # Force user to be a customer
        data['is_admin'] = False
        serializer = UserSerializer(data=data)
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        
        return Response(serializer.errors, status=400)
    
    except Exception as e:
        # Return a generic error message if something goes wrong
        return Response({"error": f"An error occurred: {str(e)}"}, status=500)

# ✅ Login & Obtain JWT Token (Stored in HTTP-Only Cookie)
@api_view(['POST'])
def login_view(request):
    try:
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)

        if user:
            refresh = RefreshToken.for_user(user)
            response = Response({
                "message": "Login successful",
            })
            
            # Set JWT tokens in HttpOnly cookies
            response.set_cookie(
                key="access_token",
                value=str(refresh.access_token),
                httponly=True,  # Prevent JavaScript access (for security)
                secure=True,    # Use True if running on HTTPS
                samesite='Lax'
            )
            response.set_cookie(
                key="refresh_token",
                value=str(refresh),
                httponly=True,
                secure=True,
                samesite='Lax'
            )
            return response

        return Response({"error": "Invalid credentials"}, status=400)
    
    except Exception as e:
        return Response({"error": f"An error occurred: {str(e)}"}, status=500)

# ✅ User Profile (View & Update with Image Upload)
@api_view(['GET', 'PATCH'])
@authentication_classes([CookieJWTAuthentication])  # Use custom authentication class
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])  # Enable file uploads
def user_profile(request):
    try:
        if request.method == 'GET':
            serializer = UserSerializer(request.user)
            return Response(serializer.data)

        if request.method == 'PATCH':
            # Handle image update via PATCH
            serializer = UserSerializer(request.user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=200)
            return Response(serializer.errors, status=400)
    
    except Exception as e:
        return Response({"error": f"An error occurred: {str(e)}"}, status=500)


# class FoodItemViewSet(viewsets.ModelViewSet):
#     queryset = FoodItem.objects.all()
#     serializer_class = FoodItemSerializer
#     permission_classes = [IsAuthenticated, IsAdminUser]  # Ensure user is authenticated
#     authentication_classes = [CookieJWTAuthentication]  # Use custom authentication

#     parser_classes = [MultiPartParser, FormParser]  # Enable image uploads

#     def perform_create(self, serializer):
#         try:
#             serializer.save()
#         except Exception as e:
#             raise ValidationError(f"Error creating food item: {str(e)}")



class FoodItemViewSet(viewsets.ModelViewSet):
    queryset = FoodItem.objects.all()
    serializer_class = FoodItemSerializer
    authentication_classes = [CookieJWTAuthentication]

    parser_classes = [MultiPartParser, FormParser]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description', 'category']
    ordering_fields = ['price', 'name']
    ordering = ['name']

    def get_permissions(self):
        """Set different permissions for different actions."""
        if self.action in ['list', 'retrieve']:  # Allow customers to view menu
            return [IsAuthenticated()]
        return [IsAdminUser()]  # Only admins can modify food items

    def get_queryset(self):
        queryset = super().get_queryset()
        category = self.request.query_params.get('category')
        min_price = self.request.query_params.get('min_price')
        max_price = self.request.query_params.get('max_price')
        
        if category:
            queryset = queryset.filter(category__icontains=category)
        if min_price:
            queryset = queryset.filter(price__gte=min_price)
        if max_price:
            queryset = queryset.filter(price__lte=max_price)
        
        return queryset


class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]  # Require authentication for all users
    authentication_classes = [CookieJWTAuthentication]

    def get_queryset(self):
        """Filter orders for the current user (if customer), or show all orders (if admin)."""
        if self.request.user.is_admin:
            return Order.objects.all()  # Admin sees all orders
        return Order.objects.filter(customer=self.request.user)  # Customer sees only their orders

    def perform_create(self, serializer):
        """Ensure only customers can place orders for themselves."""
        if not self.request.user.is_customer:
            raise PermissionDenied("Only customers can place orders.")
        
        serializer.save(customer=self.request.user)  # Auto-assign the authenticated customer

    def perform_update(self, serializer):
        """Allow only Admin to update order status."""
        if not self.request.user.is_admin:
            raise PermissionDenied("Only admins can update the order status.")
        
        order = self.get_object()
        previous_status = order.status  # Get the order status before updating
        new_status = self.request.data.get("status")  # Get the new status from the request

        # Admin can only update the status, not other fields like customer or items
        serializer.save()

        # Send email notification if order is marked as "Completed"
        if previous_status != "Completed" and new_status == "Completed":
            self.send_order_completion_email(order)


        def send_order_completion_email(self, order):
            """Send an email notification to the customer when the order is completed."""
            subject = "Your Order is Completed!"
            message = f"Dear {order.customer.username},\n\nYour order #{order.id} has been marked as Completed. Thank you for ordering with us!\n\nBest regards,\nRestaurant Team"
            recipient_email = order.customer.email
            
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,  # Ensure you set this in settings.py
                [recipient_email],
                fail_silently=False,
            )


    def create(self, request, *args, **kwargs):
        """Override the create method to ensure customers can't order for others."""
        if request.user.is_customer:
            # Ensure the request cannot contain a customer field different from the authenticated user
            if request.data.get('customer') and request.data['customer'] != str(request.user.id):
                raise PermissionDenied("You can only order for yourself.")
        
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        """Override the update method to ensure only Admin can update order status."""
        instance = self.get_object()

        if not request.user.is_admin:
            raise PermissionDenied("Only admins can update the order status.")

        return super().update(request, *args, **kwargs)

# ✅ AI-Powered Recommendations
@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])  # Use custom authentication class
@permission_classes([IsAuthenticated])
def recommendations(request):
    try:
        recommended_items = get_recommendations(request.user)
        return Response(FoodItemSerializer(recommended_items, many=True).data)
    
    except Exception as e:
        return Response({"error": f"An error occurred while fetching recommendations: {str(e)}"}, status=500)

# ✅ Logout View (Clear JWT Tokens from Cookies)
@api_view(['POST'])
def logout_view(request):
    try:
        response = Response({"message": "Logged out successfully"})   
        
        # ✅ Clear JWT cookies by setting expiration to past date
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        
        return response
    
    except Exception as e:
        return Response({"error": f"An error occurred during logout: {str(e)}"}, status=500)

