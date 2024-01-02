from django.urls import path
from api.views import (
    UserRegisterationView,
    UserLoginView,
    UserProfile,
    UserChangePassword,
    SendResetPasswordEmail,
    UserResetPaasword,
    UserViews
)

urlpatterns = [

    ########### User Authentications urls ############3
    path('UserRegistration/',UserRegisterationView.as_view()),
    path("userLogin/",UserLoginView.as_view(),name = "login"),
    path("userProfile/",UserProfile.as_view(),name = "profile"),
    path("userchangePassword/",UserChangePassword.as_view(),name = "changePassword"),
    path("sendPasswordEmail/",SendResetPasswordEmail.as_view(),name = "sendPasswordemail"),
    path("resetPassword/<str:uid>/<str:token>/",UserResetPaasword.as_view(),name = "resetpassword"),

    ######## Crude Operations Urls ######
    path("users/",UserViews.as_view({"get":"list"})),
    path("users/<int:pk>/",UserViews.as_view({"get":"get_by_id","put":"user_update"})),



]