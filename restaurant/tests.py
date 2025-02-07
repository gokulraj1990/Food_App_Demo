from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework import status
from .models import FoodItem, Order

User = get_user_model()

class RestaurantAPITestCase(APITestCase):

    def setUp(self):
        """Set up test users and sample food items."""
        # Create an admin user
        self.admin_user = User.objects.create_superuser(
            username="admin", email="admin@example.com", password="adminpass", is_admin=True, is_customer=False
        )

        # Create a customer user
        self.customer_user = User.objects.create_user(
            username="customer", email="customer@example.com", password="customerpass", is_customer=True
        )

        # Create food items
        self.food_item1 = FoodItem.objects.create(name="Burger", price=10.0, category="Fast Food")
        self.food_item2 = FoodItem.objects.create(name="Pizza", price=15.0, category="Italian")

    def authenticate(self, user):
        """Helper method to log in a user and store JWT token in cookies."""
        response = self.client.post("/api/login/", {
            "username": user.username, 
            "password": "adminpass" if user.is_admin else "customerpass"
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.client.cookies["access_token"] = response.cookies["access_token"].value
        self.client.cookies["refresh_token"] = response.cookies["refresh_token"].value

    # ✅ AUTHENTICATION TESTS
    def test_register_customer(self):
        """Test user registration."""
        data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "newpass",
            "is_customer": True
        }
        response = self.client.post("/api/register/", data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
    
    def test_login(self):
        """Test user login and JWT token retrieval."""
        data = {"username": "customer", "password": "customerpass"}
        response = self.client.post("/api/login/", data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access_token", response.cookies)

    def test_logout(self):
        """Test logout functionality."""
        self.authenticate(self.customer_user)
        response = self.client.post("/api/logout/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    # ✅ USER MANAGEMENT TESTS
    def test_get_user_profile(self):
        """Test retrieving user profile."""
        self.authenticate(self.customer_user)
        response = self.client.get("/api/users/me/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["username"], "customer")

    def test_update_user_profile(self):
        """Test updating user profile."""
        self.authenticate(self.customer_user)
        data = {"email": "updated@example.com"}
        response = self.client.patch("/api/users/me/", data, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    # ✅ MENU MANAGEMENT (ADMIN-ONLY) TESTS
    def test_admin_can_create_food(self):
        """Test that admin can create a food item."""
        self.authenticate(self.admin_user)
        data = {"name": "Pasta", "price": 12.0, "category": "Italian"}
        response = self.client.post("/api/food-items/", data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_customer_cannot_create_food(self):
        """Test that customers cannot create food items."""
        self.authenticate(self.customer_user)
        data = {"name": "Sushi", "price": 18.0, "category": "Japanese"}
        response = self.client.post("/api/food-items/", data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_food_items(self):
        """Test retrieving all food items."""
        self.authenticate(self.customer_user)
        response = self.client.get("/api/food-items/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 2)

    def test_admin_can_update_food(self):
        """Test that admin can update a food item."""
        self.authenticate(self.admin_user)
        data = {"name": "Veggie Burger", "price": 11.0}
        response = self.client.patch(f"/api/food-items/{self.food_item1.id}/", data, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["name"], "Veggie Burger")

    def test_admin_can_delete_food(self):
        """Test that admin can delete a food item."""
        self.authenticate(self.admin_user)
        response = self.client.delete(f"/api/food-items/{self.food_item1.id}/")
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    # ✅ ORDER MANAGEMENT TESTS
    def test_customer_can_place_order(self):
        """Test that a customer can place an order."""
        self.authenticate(self.customer_user)
        data = {"items": [self.food_item1.id]}
        response = self.client.post("/api/orders/", data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_customer_can_see_their_orders(self):
        """Test that a customer can see only their own orders."""
        self.authenticate(self.customer_user)
        response = self.client.get("/api/orders/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_admin_can_see_all_orders(self):
        """Test that admin can view all orders."""
        self.authenticate(self.admin_user)
        response = self.client.get("/api/orders/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_admin_can_update_order_status(self):
        """Test that an admin can update an order's status."""
        self.authenticate(self.customer_user)
        order = Order.objects.create(customer=self.customer_user, status="Pending", total_price=20.0)
        self.authenticate(self.admin_user)
        data = {"status": "Completed"}
        response = self.client.patch(f"/api/orders/{order.id}/", data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "Completed")

    # ✅ AI-POWERED RECOMMENDATION TEST
    def test_get_recommendations(self):
        """Test AI-powered food recommendations."""
        self.authenticate(self.customer_user)
        response = self.client.get("/api/recommendations/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    # ✅ SEARCH & FILTER TESTS
    def test_search_food_items(self):
        """Test searching for food items by name."""
        self.authenticate(self.customer_user)
        response = self.client.get("/api/food-items/?search=Burger")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)

    def test_filter_food_items_by_category(self):
        """Test filtering food items by category."""
        self.authenticate(self.customer_user)
        response = self.client.get("/api/food-items/?category=Fast Food")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)

    def test_filter_food_items_by_price_range(self):
        """Test filtering food items by price range."""
        self.authenticate(self.customer_user)
        response = self.client.get("/api/food-items/?min_price=5&max_price=15")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)
