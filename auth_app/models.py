from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    identifier = models.CharField(max_length=50, unique=True)
    alias_name = models.CharField(max_length=50, blank=True, null=True)
    is_blocked = models.BooleanField(default=False)
    totp_secret = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return self.username


class UserDevice(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='devices')
    uuid = models.CharField(max_length=255)
    platform = models.CharField(max_length=100, blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    last_seen = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username} device {self.uuid}"
