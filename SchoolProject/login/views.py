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
# class UserList(APIView):
#
#     def get(self, request):
#
#         users = User_info.objects.all()
#         serialize = UserSerializer(users, many=True)
#         print('get method called from views')
#         last_name = ''
#         # print(serialize.data)
#         for entry in serialize.data:
#             print(entry['first_name'])
#             if entry['first_name'] == 'Nandan':
#                 print(entry['first_name'], ' exists')
#                 last_name = entry['last_name']
#                 print('second name ', last_name)
#                 break
#         searched_last_name = User_info.objects.get(last_name=last_name)
#         print('searched_last_name ', searched_last_name)
#         User_info.objects.filter(first_name="Nandan").update(last_name="J")
#
#         return Response(serialize.data)
#
#     def post(self, request):
#         print('post method called from views')
#
#         try:
#             first_name = request.data['first_name']
#             last_name = request.data['last_name']
#
#         except KeyError as e:
#             return Response(data={"status": 406, "message": "parameter {e} missing".format(e=str(e))},
#                             status=status.HTTP_400_BAD_REQUEST)
#
#         # print(first_name)
#         # print(set_password(last_name))
#         #
#         # p = User_info(first_name=first_name,last_name=last_name)
#         # p.save()
#
#         return Response('highs')


class AccountList(APIView):
    # permission_classes = (IsAuthenticated,)

    def get(self, request):
        accounts = account.objects.all()
        serialize = AccountSerializer(accounts, many=True)
        print('get method called from views')
        return Response(serialize.data)

    def post(self, request):
        print('post method called from views')

        try:
            email = request.data['email']
            password = request.data['password']

        except KeyError as e:
            return Response(data={"status": 406, "message": "parameter {e} missing".format(e=str(e))},
                            status=status.HTTP_400_BAD_REQUEST)

        # MyAccountManager.create_superuser(self, email=email, password=password)
        # p = User_info(first_name=first_name,last_name=last_name)
        # p.save()

        return Response('highs')


class login_page(APIView):

    def get(self, request):
        accounts = account.objects.all()
        serialize = AccountSerializer(accounts, many=True)
        print('get method called from views')
        return Response(serialize.data)

    def post(self, request):
        print('post method called from views login_page')
        try:
            email = request.data['email']
            password = request.data['password']

        except KeyError as e:
            return Response(data={"status": 406, "message": "parameter {e} missing".format(e=str(e))},
                            status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, email=email, password=password)
        print('USER****************', user)
        if user is not None:
            print('entered in if')
            login(request, user)
            # redirect("AccountList")
        return Response('success')


class VerifyView(APIView):

    def get(self, request):
        token = request.GET.get('token')
        print('*************************')
        print(token)
        print('*************************')

        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            print(payload)
            user = account.objects.get(id=payload['user_id'])
            user.is_verified = True
            user.save()
            return Response({'email': 'Successfully activated'})
        except Exception as e:
            print(e)
            return Response({'email': 'Activation Failed'})


# @api_view(['POST'])
class showTemp(APIView):

    def post(self, request):

        try:
            email = request.data['email']
            password = request.data['password']
            validate_email(email)
            user = account.objects.create_user(email=email, password=password)
            token = RefreshToken.for_user(user).access_token
            print('TOKEN =', token)

        except Exception as e:
            return Response({'Error': str(e)})

        """SEND EMAIL"""
        subject = "Email verification"
        message = "Congratulations,\n " + "http://127.0.0.1:8000/verify/?token=" + str(token)
        receiver_email = email
        sender_email = "nandanjain@mastrolinks.com"
        res = send_mail(subject, message, sender_email, [receiver_email])
        print("res **", res)

        if res == 1:
            msg = "Mail sent"

        else:
            msg = "Mail NOT sent"

        content = {'message': msg}

        return Response(content)


def sending_mail(request):
    subject = "Email verification"
    message = "Congratulations"
    receiver_email = "nandan@yopmail.com"
    sender_email = "nandanmastro@gmail.com"
    res = send_mail(subject, message, sender_email, [receiver_email])

    if res == 1:
        msg = "Mail sent"

    else:
        msg = "Mail NOT sent"

    return HttpResponse(msg)


@api_view(['POST'])
def authenticate_user(request):
    # jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER

    try:
        email = request.data['email']
        password = request.data['password']
        user = auth.authenticate(email=email, password=password)

        if user:
            login(request, user)
            user_details = {'name': user.email, 'login': 'successful'}
            return Response(user_details, status=status.HTTP_200_OK)

        else:
            res = {
                'error': 'can not authenticate with the given credentials or the account has been deactivated'}
            return Response(res, status=status.HTTP_403_FORBIDDEN)

    except KeyError:
        res = {'error': 'please provide a email and a password'}
        return Response(res)


@api_view(['POST'])
def refresh_token(request):
    front_token = request.data['token']
    print(front_token)
    if tokenIsExpire(front_token):
        username = userid_from_token(front_token)
        user = account.objects.get(email=username)
        print("username :", username, " type :", type(username))
        print("user :", user, " type :", type(user))
        try:
            payload = jwt_payload_handler(user)
            token = jwt.encode(payload, settings.SECRET_KEY)

            user_details = {'name': username, 'token': token, 'role': user.is_admin}
            return Response(user_details, status=status.HTTP_200_OK)

        except Exception as e:
            raise e
    else:
        return Response({'token': 'valid'})


@api_view(['POST'])
def forgot_password(request):
    input_user = request.data['email']
    print(input_user, ' type ', type(input_user))
    user = account.objects.get(email=input_user)
    print(user, ' type ', type(user))

    if user:

        try:
            payload = jwt_payload_handler(user)
            token = jwt.encode(payload, settings.SECRET_KEY)
            print(token)
            token = token.decode('utf-8')

            subject = "Reset Password"
            message = "Click the link to reset password \n " + "http://127.0.0.1:8000/auth_for_pass/?token=" + str(
                token)
            receiver_email = input_user
            sender_email = "nandanmastro@gmail.com"
            res = send_mail(subject, message, sender_email, [receiver_email])

            if res == 1:
                msg = "Mail sent"

            else:
                msg = "Mail NOT sent"

            return HttpResponse(msg)

        except Exception as e:
            raise e
    else:
        return Response({'user': 'invalid'})


class auth_for_pass(APIView):

    def get(self, request):
        token = request.GET.get('token')
        print('************************* ', token)

        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            print(payload)
            user = account.objects.get(id=payload['user_id'])
            print(user)
            return redirect('/enter_pass/')
        except Exception as e:
            print(e)
            return Response({'email': 'verification Failed'})


class enter_pass(APIView):

    def get(self, request):
        return Response({'send': 'token & new_pwd'})

    def post(self, request):
        token = request.data['token']
        print('************************* ', token)
        new_password = request.data['new_pwd']

        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            print('payload ', payload)
            user = account.objects.get(email=payload['email'])
            print(user)

            if user:
                # print(user.set_password(new_password))
                user.set_password(new_password)
                user.save()
                return Response({'password': 'created'})

        except Exception as e:
            print(e)
            return Response({'message': 'Something went wrong'})
