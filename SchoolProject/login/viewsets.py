from rest_framework import viewsets, status

from . import models
from . import serializers


class AccountViewset(viewsets.ModelViewSet):
    queryset = models.account.objects.all()
    serializer_class = serializers.AccountSerializer
