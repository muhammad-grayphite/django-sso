from django.urls import path

from . import views

app_name = 'accounts'

urlpatterns = [
    path('register/', views.UserRegistrationView.as_view(), name='register'),
    path('login/', views.UserLoginView.as_view(), name='login'),
    path('profile/', views.UserProfileView.as_view(), name='profile'),
    path('change-password/', views.UserChangePasswordView.as_view(), name='change_password'),

    path("google-login/", views.GoogleLogin.as_view(), name="google_login"),
    path('facebook-login/', views.FacebookLogin.as_view(), name='fb_login')
]
