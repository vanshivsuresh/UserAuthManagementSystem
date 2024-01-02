from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from api.serializers import(
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    UserChangePasswordSerializer,
    SendResetPasswordEmailSerializer,
    UserResetPaaswordSerializer,
    UserListViewsSerializer,
    UserUpdateSerializer)

from django.contrib.auth import authenticate
from api.models import User
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated,IsAdminUser
import logging
from api.base import BaseViewset
from api.permissions import (
    IsAdminUser,
    IsRegularUser)

logger = logging.getLogger(__name__)


# Create your views here.

# create Token mannually..
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

######################### Login,Registrations,UserProfile,ChangePassword,ResetPassword ############


class UserRegisterationView(APIView):

    def post(self,request):

        serializer = UserRegistrationSerializer(data = request.data)
        if serializer.is_valid(raise_exception = True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response(
                {
                 "status":status.HTTP_201_CREATED,
                 "msg":"user Registration successuully...",
                 "token":token,
                 "resuts":[serializer.data],
                 
                 }
                )

        return Response({"status":status.HTTP_400_BAD_REQUEST,"msg":"user not Registration "})


class UserLoginView(APIView):
    def post(self,request,format = None):

        serializer = UserLoginSerializer(data = request.data)
        if serializer.is_valid(raise_exception= True):
            email = serializer.data.get("email")
            password = serializer.data.get("password")
            # logger.debug("Before authenticate - Email: %s, Password: %s", email, password)
            user = authenticate(email = email,password =  password)
            # logger.debug("After authenticate - User: %s", user)
            if user is not None:
                token = get_tokens_for_user(user)
                user = UserLoginSerializer(user).data

                return Response({
                    "status":status.HTTP_200_OK,
                    "message":"user loggedin successfully..",
                    "token": token,
                    "result":[serializer.data]
                    
                    
                    })
                
            else:
                return Response({"status":status.HTTP_404_NOT_FOUND,"message":"User password and email not found"})
        
        return Response({"error":serializer.error_messages,"status":status.HTTP_400_BAD_REQUEST})

class UserProfile(APIView):

    permission_classes = [IsAuthenticated]
    
    def get(self,request,format = None):
        print("@@@@@@@@",request.user)
        serializer = UserLoginSerializer(request.user)
        return Response({"data":serializer.data})
    
class UserChangePassword(APIView):
    permission_classes = [IsAuthenticated]
    def post(self,request,format = None):
        serializer = UserChangePasswordSerializer(data = request.data,
                                                  context = {"user":request.user})
        if serializer.is_valid(raise_exception= True):
            return Response({"status":status.HTTP_201_CREATED,"msg":"user password changes successuully...",})
        return Response({"status":status.HTTP_404_NOT_FOUND,"message":"password and confirm password does not match"})
    

class SendResetPasswordEmail(APIView):
    def post(self,request,format = None):
        serializer = SendResetPasswordEmailSerializer(data = request.data)
        if serializer.is_valid(raise_exception= True):
            return Response(
                {
                    "status":status.HTTP_201_CREATED,
                    "msg":"Link send on your email please check your emial"}
                )
        return Response(
            {
                "status":status.HTTP_404_NOT_FOUND,
                "message":"please enter correct email."}
            )
    
class UserResetPaasword(APIView):
    def post(self,request,uid,token,format = None):
        serializer = UserResetPaaswordSerializer(
                    data = request.data ,
                    context = {"uid":uid,"token":token}
                    )
        if serializer.is_valid(raise_exception=True):
             return Response(
                {
                    "status":status.HTTP_201_CREATED,
                    "msg":"password change successfully"}
                )
        return Response(
            {
                "error":serializer.errors,
                "status":status.HTTP_404_NOT_FOUND,
                "message":""}
            )
    

##################### CRUDE OPERATIONS ###########################  
class UserViews(BaseViewset):

    permission_classes = [IsAuthenticated,IsAdminUser]

    def list (self,request):
      data = User.objects.all()
      serializer = UserListViewsSerializer(data, many = True)

      return Response(
            {
                "success": True,
                "status": "success",
                "message": "",
                "results": serializer.data,
            }
        )    


    def get_by_id(self, request, pk):
        try:
            existing_user = User.objects.get(pk=pk)
            serializer = UserListViewsSerializer(existing_user)

            return Response(
                {
                    "success": True,
                    "status": "success",
                    "message": "",
                    "results": [serializer.data],
                }
            )
        except User.DoesNotExist:
            return Response(
                {"success": False, "error": "User not found"},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            print("Exception ====> ", e)
            return Response(
                {"success": False, "error": "Something went wrong"},
                status=status.HTTP_400_BAD_REQUEST,
            )

    def user_update(self, request, pk):
        user = User.objects.get(pk=pk)
        if not user:
            return Response( 'User not found.', status=status.HTTP_404_NOT_FOUND)
        serializer = UserUpdateSerializer(user, data=request.data, partial=True
        )


        if serializer.is_valid(raise_exception = True):
            serializer.save()
            return Response(

                    {
                    "success": True,
                    "status": "success",
                    "message": "User Data Update Sucessfully.",
                    "results": [serializer.data],
                }
            )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)    
