from rest_framework import serializers
from api.models import User
from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.exceptions import ValidationError
from api.utils import Utils
from rest_framework.response import Response

class UserRegistrationSerializer(serializers.ModelSerializer):

    password2 = serializers.CharField(style = {'input_type':"password"},write_only = True)
    class Meta:
        model = User
        # fields = ['email','name','password','password2','tc','is_active']
        fields = "__all__"
        extra_kwargs = {
                        'password':{'write_only':True}
                        
                        }
        
    def validate(self, data):
        password = data.get("password")
        password2 = data.get("password2")

        if password != password2:
            raise serializers.ValidationError("password and confirm password does not match.")
        return data
    
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    
    

class UserLoginSerializer(serializers.ModelSerializer):

    email = serializers.EmailField(max_length = 255)
    class Meta:
        model = User
        fields = ["email","password"]

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields =['id','email','password']

class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length = 200,style = {"input_type":"password"},write_only =True)
    password2 = serializers.CharField(max_length = 200,style = {"input_type":"password2"},write_only =True)
    class Meta:
        model = User
        fields =['password','password2']

    def validate(self, data):
        password = data.get("password")
        password2 = data.get("password2")
        user = self.context.get("user")
        print("@@@@@@@@@@@@@2222",user)
        if password != password2:
            raise serializers.ValidationError("password and confirm password does not match.")
        user.set_password("password")
        # print("##############",user.set_password("password"))
        user.save()
        return data

class SendResetPasswordEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length = 255)
    class Meta:
        model = User
        fields = ['email']

    def validate(self, data):
        email = data.get("email")
        if User.objects.filter(email = email).exists():
            user = User.objects.get(email = email)
            # uid = user.id
            # token = PasswordResetTokenGenerator(user)
            # print("@@@@@222",uid,"##############",token)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            link = 'http://localhost:3000/api/user/reset/'+uid+'/'+token

            #Send Emial
            body = "Click on the given link and Reset Your Password"+link
            data = {
                'subject':"Change Your password",
                "body":body,
                "to_email":user.email
                }
            Utils.send_email(data)
            return data

        else:
            pass   
        return data

class UserResetPaaswordSerializer(serializers.Serializer):

    try:
        password = serializers.CharField(max_length = 200,style = {"input_type":"password"},write_only =True)
        password2 = serializers.CharField(max_length = 200,style = {"input_type":"password2"},write_only =True)
        class Meta:
            model = User
            fields =['password','password2']

        def validate(self, data):
            password = data.get("password")
            password2 = data.get("password2")
            uid = self.context.get("uid")
            token = self.context.get("token")
            if password != password2:
                raise serializers.ValidationError("password and confirm password does not match.")
            
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id = id)
            # token = PasswordResetTokenGenerator().check_token(user,token)
            if not PasswordResetTokenGenerator().check_token(user,token):
                raise ValidationError("token is ecpired")
            
            user.set_password("password")
            # print("##############",user.set_password("password"))
            user.save()
            return data
    except DjangoUnicodeDecodeError as Identifier:
        # PasswordResetTokenGenerator().check_token(user,token)
        raise Exception("Exception is :",Identifier)

class UserListViewsSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"
  

class UserUpdateSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style = {'input_type':"password"},write_only = True)
    class Meta:
        model = User
        # fields = ['email','name','password','password2','tc','is_active']
        fields = "__all__"
        extra_kwargs = {
                        'password':{'write_only':True}
                        
                        }
        
    def update(self, instance, validated_data):
        password = validated_data.get('password')
        email = validated_data.get("email")
        name = validated_data.get("name")
        tc = validated_data.get("tc")

        instance.email = email
        instance.name = name
        instance.tc = tc
        if password:
            instance.set_password(password)
        instance.save()
        return instance