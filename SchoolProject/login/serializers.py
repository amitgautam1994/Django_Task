from rest_framework import serializers
from .models import account
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import Group


class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = account
        # fields = '__all__'
        fields = ['id', 'first_name', 'last_name', 'email', 'password', 'is_admin', 'is_teacher','groups']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data.get('password'))
        user = account.objects.create(**validated_data)

        if validated_data['is_admin']:
            group = Group.objects.get(name='admin')
            user.groups.add(group)

        else:
            if validated_data['is_teacher']:
                group = Group.objects.get(name='teacher')
                user.groups.add(group)
            else:
                group = Group.objects.get(name='student')
                user.groups.add(group)

        return super(AccountSerializer, self)