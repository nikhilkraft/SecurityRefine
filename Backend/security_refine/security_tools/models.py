from django.db import models

# Secure file sharing (encrypt and decryt file)
class SecureFile(models.Model):
    file = models.FileField(upload_to='secure_files/')
    encrypted = models.BooleanField(default=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
#Online text encryption and decryption

class EncryptedMessage(models.Model):
    encrypted_text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Message {self.id}"

# Email Privacy Checker
class EmailCheck(models.Model):
    email = models.CharField(max_length=255)
    is_secure = models.BooleanField(default=False)
    privacy_risks = models.TextField(blank=True)

    def __str__(self):
        return self.email
    
    
# Metadata Stripper

class UploadedFile(models.Model):
    file = models.FileField(upload_to="uploads/")
    stripped_file = models.FileField(upload_to="stripped/", blank=True, null=True)

# Phishing URL scanner
class ScannedURL(models.Model):
    url = models.URLField(unique=True)
    is_phishing = models.BooleanField(default=False)
    checked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url