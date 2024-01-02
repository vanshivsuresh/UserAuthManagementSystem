from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.contrib.auth.models import Group, Permission
# Create your models here.

#custome user models
class UserManager(BaseUserManager):
    def create_user(self, email, name,tc, password=None,password2 = None,role = "user",**extra_fields):
        """
        Creates and saves a User with the given email, name,tc and password.
        """
        if not email:
            raise ValueError("Users must have an email address")

        # role = extra_fields.pop('role', 'user')

        user = self.model(
            email=self.normalize_email(email),
            name=name,
            tc=tc,
            role = role,
             **extra_fields
        )
        user.is_active = True
        user.set_password(password)
        user.save(using=self._db)
        return user
    



    def create_superuser(self, email, name,tc, password=None,**extra_fields):
        """
        Creates and saves a superuser with the given email, name,tc and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        # role = extra_fields.pop('role', 'admin')

        user = self.create_user(
            email,
            password=password,
            name=name,
            tc=tc,
            role='admin',
            **extra_fields
        )
        # user.role = role
        user.is_admin = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser,PermissionsMixin):
    email = models.EmailField(
        verbose_name="Email",
        max_length=255,
        unique=True,
    )
    name = models.CharField(max_length = 200)
    tc = models.BooleanField()

    ####### Permissions and Role
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    ####### Tracking 
    date_joined = models.DateTimeField(auto_now_add=True, null=True)
    created_at = models.DateTimeField(auto_now_add = True)
    update_at = models.DateTimeField(auto_now = True)
    

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name","tc"]

    def __str__(self):
        return self.email
    
    ROLE_CHOICES = (
    ("admin", "Admin"),
    ("user", "User"),
    )
    role = models.CharField(max_length=64, choices=ROLE_CHOICES, default="user")


    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    # @property
    # def is_staff(self):
    #     "Is the user a member of staff?"
    #     # Simplest possible answer: All admins are staff
    #     return self.is_admin
    



    # admin_group, created = Group.objects.get_or_create(name='Admins')
    # user_group, created = Group.objects.get_or_create(name='Users')

    # admin_permissions = Permission.objects.filter(codename__startswith='admin')
    # user_permissions = Permission.objects.filter(codename__startswith='user')

    # admin_group.permissions.set(admin_permissions)
    # user_group.permissions.set(user_permissions)

    # admin_users = User.objects.filter(role='admin')
    # user_users = User.objects.filter(role='user')

    # admin_group.user_set.set(admin_users)
    # user_group.user_set.set(user_users)