from django.urls import path
from .views import LoginView, ProtectedView, CreateUserView, UpdateUserView, DeleteUserView

urlpatterns = [
    path('login/', LoginView.as_view()),
    path('protected/', ProtectedView.as_view()),
    path('users/create/', CreateUserView.as_view()),
    path('users/update/', UpdateUserView.as_view()),
    path('users/delete/<int:user_id>/', DeleteUserView.as_view()),
]
