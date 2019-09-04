from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import MyUser


class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=128,
        min_length=8,
        write_only=True
    )

    class Meta:
        model = MyUser
        fields = ['first_name', 'last_name', 'email', 'password']

    def create(self, validated_data):
        user = MyUser.objects.create_user(
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        user.save()
        return user


class VerifyOTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = MyUser
        fields = ['otp', 'email']


class ForgotPasswordSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = MyUser
        fields = ('email',)


class ResetPasswordSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    old_password = serializers.CharField(max_length=255)
    new_password = serializers.CharField(max_length=255)
    confirm_password = serializers.CharField(max_length=255)

    class Meta:
        model = MyUser
        fields = ('email', 'old_password', 'new_password', 'confirm_password')


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=255)
    # username = serializers.CharField(max_length=255, read_only=True)
    password = serializers.CharField(max_length=128, write_only=True)
    token = serializers.CharField(max_length=255, read_only=True)

    class Meta:
        fields = ('email','password','token')
    #you can also validate data here
    # def validate(self, data):

    #     email = data.get('email', None)
    #     password = data.get('password', None)
    #     if email is None:
    #         raise serializers.ValidationError(
    #             'An email address is required to log in.'
    #         )

    #     if password is None:
    #         raise serializers.ValidationError(
    #             'A password is required to log in.'
    #         )

    #     user = authenticate(username=email, password=password)

    #     # if not user.is_active:
    #     #     raise serializers.ValidationError(
    #     #         'This user has been deactivated.'
    #     #     )

    #     return {
    #         'email': user.email,
    #         'token': user.token
    #     }
