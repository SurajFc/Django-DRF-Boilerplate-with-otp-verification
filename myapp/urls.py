from django.urls import path
from .views import LoginAPIView, RegistrationAPIView, VerifyOTPView, ForgotPasswordView, ResetPasswordView

app_name='myapp'

urlpatterns = [
    path('register', RegistrationAPIView.as_view()), #Registeration
    path('login', LoginAPIView.as_view()), #Login after otp verification
    path('verify', VerifyOTPView.as_view()), #otp Verify
    path('forgot', ForgotPasswordView.as_view(), name='forgot-password'), #forgot Password
    path('reset', ResetPasswordView.as_view(), name='reset-password'), #Resetting the Password after Login


    ]