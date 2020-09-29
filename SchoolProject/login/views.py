from django.http import HttpResponse
from django.shortcuts import render, redirect
from keyring import set_password
from rest_framework.authtoken.serializers import AuthTokenSerializer

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes

from rest_framework.response import Response
from rest_framework.views import APIView

from .models import  account, MyAccountManager
from .serializers import AccountSerializer

from django.contrib.auth import authenticate, login, user_logged_in
from django.contrib.auth.models import User, auth

from rest_framework.permissions import IsAuthenticated, AllowAny

from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError

from django.core.mail import send_mail

# from rest_framework_simplejwt.tokens import RefreshToken
import jwt
from django.conf import settings
from rest_framework_jwt.settings import api_settings

from .verify_token import tokenIsExpire, userid_from_token

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
from django.core.validators import validate_email


# Create your views here.
class UserList(APIView):

    def get(self, request):

        users = User_info.objects.all()
        serialize = UserSerializer(users, many=True)
        print('get method called from views')
        last_name = ''
        # print(serialize.data)
        for entry in serialize.data:
            print(entry['first_name'])
            if entry['first_name'] == 'Nandan':
                print(entry['first_name'], ' exists')
                last_name = entry['last_name']
                print('second name ', last_name)
                break
        searched_last_name = User_info.objects.get(last_name=last_name)
        print('searched_last_name ', searched_last_name)
        User_info.objects.filter(first_name="Nandan").update(last_name="J")

        return Response(serialize.data)

    def post(self, request):
        print('post method called from views')

        try:
            first_name = request.data['first_name']
            last_name = request.data['last_name']

        except KeyError as e:
            return Response(data={"status": 406, "message": "parameter {e} missing".format(e=str(e))},
                            status=status.HTTP_400_BAD_REQUEST)

        # print(first_name)
        # print(set_password(last_name))
        #
        # p = User_info(first_name=first_name,last_name=last_name)
        # p.save()

        return Response('highs')

