import os,jwt
from datetime import datetime, timedelta
from django.conf import settings
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin
)
from django.db import models
import uuid
from uuid import UUID
from json import JSONEncoder
JSONEncoder_olddefault = JSONEncoder.default
def JSONEncoder_newdefault(self, o):
    if isinstance(o, UUID): return str(o)
    return JSONEncoder_olddefault(self, o)
JSONEncoder.default = JSONEncoder_newdefault


class UserManager(BaseUserManager):
    def create_user(self, email, first_name, last_name, password=None,**kwargs):

        if first_name is None:
            raise TypeError('Users must have a First Name')

        if last_name is None:
            raise TypeError('Users must have a Last Name')
        if email is None:
            raise TypeError('Users must have an email address.')

        user = self.model(first_name=first_name, last_name=last_name, email=self.normalize_email(email),**kwargs)
        user.set_password(password)
        user.save()

        return user

    def create_superuser(self, email, password):
        """
        Create and return a `User` with superuser (admin) permissions.
        """
        # if password is None:
        #     raise TypeError('Superusers must have a password.')

        # user = self.create_user(email, password, last_name='User')
        # user.is_superuser = True
        # user.is_staff = True
        # user.is_active = True
        # user.save()

        # return user

        if not email:
            raise ValueError('Users must have an email address.')

        user = self.model(
            first_name='Super',
            last_name='User',
            email=self.normalize_email(email),
            is_staff=True,
            is_superuser=True,

        )

        user.set_password(password)
        user.is_active = True
        user.save(using=self._db)
        return user




class MyUser(AbstractBaseUser, PermissionsMixin):
    user_id = models.CharField(primary_key=True, default=uuid.uuid4, blank=False, unique=True, editable=False,
                               max_length=500, name=("user_id"), verbose_name=("User ID"))
    first_name = models.CharField(max_length=255, blank=False)
    last_name = models.CharField(max_length=255, blank=False)
    mobile = models.CharField(max_length=11, blank=True)
    email = models.EmailField(db_index=True, unique=True)
    is_confirmed = models.BooleanField(default=False) #default is True when not using otp email verification
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    otp = models.IntegerField(editable=False, default=False) #storing otp
    is_used = models.BooleanField(default=False)  # it becomes true when otp stored in db is already used

    USERNAME_FIELD = 'email'   #by default it takes username. but we  change  to  email
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return "{}".format(self.user_id)

    def __user_id__(self):
        return self.user_id

    class Meta:
        db_table = 'MyUser'
        managed = True

    @property
    def token(self):
        return self._generate_jwt_token()

    def _generate_jwt_token(self):
        dt = datetime.now() + timedelta(days=60)

        token = jwt.encode({
            'id': self.pk,
            'exp': int(dt.strftime('%s'))
        }, settings.SECRET_KEY, algorithm='HS256')

        return token.decode('utf-8')

