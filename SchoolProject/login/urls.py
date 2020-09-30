from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name="index"),
    path('auth', views.authenticate_user, name="login"),
    path('for_pass/', views.forgot_password),  # enter email so that a verification mail can be sent
    path('auth_for_pass/', views.auth_for_pass.as_view()),  # auth the user
    path('enter_pass/', views.enter_pass.as_view()),  # enter password to update it

]
