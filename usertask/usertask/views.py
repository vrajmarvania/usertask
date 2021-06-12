import json
import json.decoder
import jwt
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import HttpResponse, JsonResponse, response

from django.shortcuts import render, redirect
from django.template.defaulttags import url
from pyasn1.compat.octets import null

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from app.models import Address


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


def sing_in(request):
    if not request.session.has_key('token'):

        if request.method == 'POST':
            Email = request.POST.get('Email')
            password = request.POST.get('password')
            print(Email, password)
            try:
                user = User.objects.all().filter(email=Email)
                if len(user) == 0:
                    param = {'error': "user not found"}
                    return render(request, 'sing_in.html', param)
                print(len(user))
                user = user[0]
                print(user)


            except User.DoesNotExist:
                return Response({'Error': "Invalid username/password"}, status="400")
            if user:
                payload = {
                    'id': user.id,
                    'email': user.email,
                }
                secret_key = "abcdefghi"

                jwt_token = {'token': jwt.encode(payload, secret_key)}

                request.session['token'] = jwt_token.get("token").decode("utf-8")

                return redirect('index')

            return render(request, 'sing_up.html')

        return render(request, 'sing_in.html')
    return redirect('index')


def sing_up(request):
  if not request.session.has_key('token'):

    if request.method == 'POST':
        un = request.POST.get('Username')
        UserEmail = request.POST.get('UserEmail')
        password = request.POST.get('password')
        password1 = request.POST.get('password1')
        Add = request.POST.get('Address')
        print(un, UserEmail, password, password1, Add)
        if (password != password1):
            sum = {'error': "Plese Enter a same password"}
            return render(request, 'sing_up.html', sum)

        try:
            usr = User.objects.get(username=un)
            sum = {'error': "Username already taken!!! Please try another Username."}
            return render(request, 'sing_up.html', sum)

        except:
            pass
        try:
            usr = User.objects.get(email=UserEmail)
            sum = {'error': "Email already taken!!! Please try another Email."}
            return render(request, 'sing_up.html', sum)

        except:
            pass
        user = User.objects.create_user(
            username=un,
            password=password,
            email=UserEmail,
        )
        user.save()
        data = Address(user=user, Address=Add)
        data.save()
        sum = {'error': "data is submited"}
        return render(request, 'sing_in.html', sum)

    sum = {}
    return render(request, 'sing_up.html', sum)
  return redirect('index')


def index(request):

    if request.session.has_key('token'):
        if request.session.has_key('token'):
            token = request.session['token']
            secret_key = "abcdefghi"

            payload = jwt.decode(token, secret_key, algorithms=['HS256'])
            print(payload)
            data = User.objects.all()
            data = list(data)
            add = Address.objects.all()
            print(add)
            param = {'data': data, 'address': list(add)}
            return render(request, 'index.html', param)
    return redirect('sing_in')


def logout(request):
    auth.logout(request)
    return redirect("sing_in")


def edit(request, id):
    if request.method == 'POST':
        id = int(id)
        un = request.POST.get('Username')
        UserEmail = request.POST.get('UserEmail')
        Add = request.POST.get('Address')
        print(id)
        u = User.objects.get(id=int(id))
        u.address.Address = Add
        u.email = UserEmail
        u.save()

        return redirect("index")


def Delete(request, id):
    id = int(id)
    print(id)
    # User.objects.get(id=int(id)).delete()
    print("___________________")
    print(User.objects.get(id=int(id)).delete())

    return redirect("index")
