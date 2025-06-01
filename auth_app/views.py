from django.contrib.auth import authenticate, get_user_model
from django.shortcuts import get_object_or_404

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from .models import UserDevice
from .serializers import UserSerializer

import pyotp

User = get_user_model()


# ---------------------------
# Login View
# ---------------------------
class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        device_info = request.data.get('device_info', {})
        totp_code = request.data.get('totp')

        user = authenticate(username=username, password=password)
        if user is None:
            return Response({'status': False, 'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        # Optional TOTP verification
        # if user.totp_secret:
        #     totp = pyotp.TOTP(user.totp_secret)
        #     if not totp_code or not totp.verify(totp_code):
        #         return Response({'status': False, 'error': 'Invalid or missing TOTP code'}, status=status.HTTP_401_UNAUTHORIZED)

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
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        })


# ---------------------------
# Protected View
# ---------------------------
class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({'message': f'Hello {request.user.username}, this is a protected view!'})


# ---------------------------
# Create User View
# ---------------------------
class CreateUserView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({'status': True, 'user': UserSerializer(user).data}, status=status.HTTP_201_CREATED)
        return Response({'status': False, 'errors': serializer.errors}, status=422)


# ---------------------------
# Update User View
# ---------------------------
class UpdateUserView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        serializer = UserSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'status': True, 'user': serializer.data})
        return Response({'status': False, 'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


# ---------------------------
# Delete User View (Authenticated user deletes self)
# ---------------------------
class DeleteUserView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, user_id):
        user = get_object_or_404(User, id=user_id)
        user.delete()
        return Response({'status': True, 'message': 'User deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)