from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import UserDevice
import pyotp

class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        device_info = request.data.get('device_info', {})
        totp_code = request.data.get('totp')

        user = authenticate(username=username, password=password)

        if user is None:
            return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        # Optional TOTP verification
        if user.totp_secret:
            totp = pyotp.TOTP(user.totp_secret)
            if not totp_code or not totp.verify(totp_code):
                return Response({'detail': 'Invalid or missing TOTP code'}, status=status.HTTP_401_UNAUTHORIZED)

        # Track device info
        UserDevice.objects.update_or_create(
            user=user,
            uuid=device_info.get('uuid'),
            defaults={
                'platform': device_info.get('platform'),
                'ip_address': request.META.get('REMOTE_ADDR'),
            }
        )

        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user_id': user.id,
            'username': user.username,
        })
