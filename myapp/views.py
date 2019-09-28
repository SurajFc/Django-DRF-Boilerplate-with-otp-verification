from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
import pyotp, random, jwt
from django.conf import settings
from django.core.mail import send_mail
from .models import MyUser
from .renderers import UserJSONRenderer
from .serializers import LoginSerializer, RegistrationSerializer, VerifyOTPSerializer, ForgotPasswordSerializer, ResetPasswordSerializer
from django.contrib.auth import authenticate
from passlib.hash import django_pbkdf2_sha256 as handler
from rest_framework_jwt.serializers import VerifyJSONWebTokenSerializer
from django.core.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework_jwt.settings import api_settings

#generating OTP
def generateOTP():
    global totp
    totp = pyotp.TOTP('base32secret3232',interval = 300) #set interval(time of the otp expiration) according to your need in seconds.
    one_time = totp.now()
    return one_time

#verifying OTP
def verifyOTP(one_time):
    answer = totp.verify(one_time)
    return answer


class RegistrationAPIView(APIView):
    queryset = MyUser.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegistrationSerializer
    renderer_classes = (UserJSONRenderer,)

    def get(self, request):
        return Response({'Status': 'You cannot view all users data.....'})

    def post(self, request):
        email = request.data['email']
        print(email)

        data = MyUser.objects.filter(email=email)
        print('data ', data)

        if data.exists():
            return Response({'msg': 'Already registered'}, status=status.HTTP_409_CONFLICT)
        else:
            serializer = self.serializer_class(data=request.data)
            print("ser", serializer)
            first_name = request.data['first_name']

            if serializer.is_valid(raise_exception=True):
                serializer.save()
                subject = 'Welcome'
                message = f'Welcome {first_name} Your OTP is : ' + generateOTP()
                email_from = settings.EMAIL_HOST_USER
                recipient_list = [email]
                message = message
                send_mail(
                    subject,
                    message,
                    email_from,
                    recipient_list,
                    fail_silently=False,
                )

                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response({"Error": "Sign Up Failed"}, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTPView(APIView):
    queryset = MyUser.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = VerifyOTPSerializer

    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        email = request.data['email']
        one_time = request.data['otp']
        print('one_time_password', one_time)
        one = verifyOTP(one_time)
        print('one', one)
        if one:
            MyUser.objects.filter(email=email).update(is_confirmed=True, is_used=True, otp=one_time)
            return Response({'msg': 'OTP verfication successful'}, status=status.HTTP_200_OK)
        else:
            return Response({'msg': 'OTP verfication Failed'}, status=status.HTTP_400_BAD_REQUEST)

#it will send the mail with changed password which is generated randomly
class ForgotPasswordView(APIView):
    serializer_class = ForgotPasswordSerializer
    queryset = MyUser.objects.all()
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        #Generating Random Password of specific Type or use according to your need
        str_1 = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
                 'U', 'V', 'W', 'X', 'Y', 'Z']
        str_2 = ['!', '@', '#', '$', '%', '&', '*', '/', '-', '+']
        str_3 = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

        str = random.choice(str_1)
        for s in range(4):
            str += random.choice(str_1).lower()
        str += random.choice(str_2)
        for x in range(2):
            str += random.choice(str_3)

        password = handler.hash(str)

        if serializer.is_valid():
            email = request.data['email']
            print(email)
            MyUser.objects.filter(email=email).update(password=password)

            subject = 'Forgot Password Request'
            message = 'Your request for Forgot Password has been received, your new password is ' + str
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [email]

            send_mail(
                subject,
                message,
                email_from,
                recipient_list,
                fail_silently=False,
            )
            return Response({'msg': 'done'}, status=status.HTTP_200_OK)
        else:
            return Response({'msg': 'Not a valid request'}, status=status.HTTP_400_BAD_REQUEST)

#for changing the password
class ResetPasswordView(APIView):
    serializer_class = ResetPasswordSerializer
    queryset = MyUser.objects.all()
    permission_classes = (AllowAny,)

    def post(self, request):
        token1 = request.META['HTTP_AUTHORIZATION']
        token = token1.split(' ')[1]
        data = {'token': token}
        payload_decoded = jwt.decode(token, settings.SECRET_KEY)
        try:
            valid_data = VerifyJSONWebTokenSerializer().validate(data)
            user_id = valid_data['user']
            self.request.user = user_id
        except jwt.ExpiredSignatureError:
            return Response(status=440)

        serializer = ResetPasswordSerializer(data = request.data)
        if serializer.is_valid():
            new_password = request.data['new_password']
            confirm_password = request.data['confirm_password']

            if new_password == confirm_password:
                password = handler.hash(new_password)
                email = request.data['email']
                MyUser.objects.filter(email=email, user_id=user_id).update(password=password)

                return Response({'msg': 'Password updated successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'msg': 'New Password and Confirm Password does not match, please enter again'}, status=status.HTTP_409_CONFLICT)
        else:
            return Response({'msg': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(APIView):
    permission_classes = (AllowAny,)
#     renderer_classes = (UserJSONRenderer,)
    serializer_class = LoginSerializer
    queryset = MyUser.objects.all()

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        email = request.data['email']
        print('email', email)
        filter_data = MyUser.objects.filter(email=email).values('is_active')
        print('filter_data', filter_data)
        if filter_data.exists() :  
            val = filter_data[0]['is_active']
        else:
            return Response("Email is not Registered",status=status.HTTP_400_BAD_REQUEST)

        if val:
            if serializer.is_valid():
                user = authenticate(username=request.data['email'], password=request.data['password'])
                if user is not None and user.is_confirmed and user.is_active:  #change according to yourself
                    jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
                    jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
                    payload = jwt_payload_handler(user)
                    token = jwt_encode_handler(payload)
                    return Response({'msg': 'Login successful', 'is_confirmed': user.is_confirmed, 'token': token,
                                     'first_name': user.first_name, 'last_name': user.last_name,
                                      }, status=status.HTTP_200_OK)
                else:
                    return Response({'msg': 'Account not approved or wrong Password.'}, status=status.HTTP_409_CONFLICT)
            else:
                return Response({'msg': 'Invalid data'}, status=status.HTTP_401_UNAUTHORIZED)

        else:
            return Response({'Error': 'Not a valid user'}, status=status.HTTP_401_UNAUTHORIZED)


