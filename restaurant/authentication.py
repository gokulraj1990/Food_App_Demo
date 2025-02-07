import logging
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken
from datetime import datetime

class CookieJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        token = request.COOKIES.get('access_token')

        if not token:
            return None  # No token, let DRF handle it as unauthenticated

        try:
            access_token = AccessToken(token)
            exp_timestamp = access_token['exp']
            current_timestamp = datetime.utcnow().timestamp()

            if current_timestamp > exp_timestamp:
                raise AuthenticationFailed("Token has expired.")

            # ✅ Ensure user is retrieved correctly
            user_id = access_token['user_id']
            from django.contrib.auth import get_user_model
            User = get_user_model()
            user = User.objects.get(id=user_id)

            logging.debug(f"Authenticated user: {user}")
            return (user, None)
        except Exception as e:
            logging.error(f"Authentication failed: {str(e)}")
            raise AuthenticationFailed(f"Invalid token: {str(e)}")

        return None
