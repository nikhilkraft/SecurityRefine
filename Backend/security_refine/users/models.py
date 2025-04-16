from django.db import models



class UserRegistrationModel(models.Model):
    firstname = models.CharField(max_length=255)
    lastname = models.CharField(max_length=255, unique=True)
    email = models.EmailField(unique=True)
    password = models.TextField(max_length=255)  # Store encrypted passwords


