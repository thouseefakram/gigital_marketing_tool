from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    UserListSerializer
)
from .models import User, PasswordResetToken
from .utils import generate_jwt_token, send_password_reset_email,generate_password_reset_token
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
import uuid

class UserRegistrationView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token = generate_jwt_token(user)
            return Response({
                'message': 'User registered successfully',
                'user': {
                    'email': user.email,
                    'full_name': user.full_name,
                    'language': user.language
                },
                'token': token
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class UserListView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Check if user is admin
        if not request.user.is_superuser:
            return Response(
                {'message': 'You do not have permission to perform this action.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        users = User.objects.all().order_by('-created_at')
        serializer = UserListSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class UserLoginView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        # Hardcoded admin login - now returns token like normal users
        if email == 'admin@gmail.com' and password == 'admin':
            try:
                admin_user = User.objects.get(email='admin@gmail.com')
            except User.DoesNotExist:
                # Create admin user if doesn't exist
                admin_user = User.objects.create_superuser(
                    email='admin@gmail.com',
                    full_name='Admin',
                    password='admin'
                )
            
            token = generate_jwt_token(admin_user)
            return Response({
                'message': 'Login successful',
                'user': {
                    'email': admin_user.email,
                    'full_name': admin_user.full_name
                },
                'token': token  # Make sure to include this
            }, status=status.HTTP_200_OK)

        # Normal user login flow
        serializer = UserLoginSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = serializer.validated_data['user']
            token = generate_jwt_token(user)
            return Response({
                'message': 'Login successful',
                'user': {
                    'email': user.email,
                    'full_name': user.full_name
                },
                'token': token
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)

class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)
            reset_token = generate_password_reset_token(user)
            
            # Instead of sending email, return the token in response
            return Response({
                'message': 'Password reset token generated',
                'reset_token': reset_token,
                'expires_in': settings.PASSWORD_RESET_TIMEOUT
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            reset_token = serializer.validated_data['reset_token']
            user = reset_token.user
            new_password = serializer.validated_data['new_password']
            
            user.set_password(new_password)
            user.save()
            
            # Delete the used token
            reset_token.delete()
            
            return Response({
                'message': 'Password has been reset successfully'
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class ProtectedTestView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        return Response({
            'message': 'This is a protected view',
            'user': {
                'email': request.user.email,
                'full_name': request.user.full_name
            }
        })