from django.http import JsonResponse
from rest_framework.decorators import api_view
import pyzxcvbn
from django.core.files.base import ContentFile
from django.http import JsonResponse, HttpResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import EmailCheck, EncryptedMessage, SecureFile
from cryptography.fernet import Fernet
import base64

@api_view(['POST'])
def check_password_strength(request):
    data = request.data
    password = data.get("password", "")
    
    if not password:
        return JsonResponse({"error": "Password is required"}, status=400)

    result = pyzxcvbn.zxcvbn(password)

    response = {
        "score": result['score'],  # Score (0 to 4)
        "feedback": result['feedback']
    }
    
    return JsonResponse(response)

# Password Generator
from django.http import JsonResponse
from rest_framework.decorators import api_view
import random
import string

@api_view(['GET'])
def generate_password(request):
    length = int(request.GET.get("length", 12))
    use_lower = request.GET.get("lower", "true").lower() == "true"
    use_upper = request.GET.get("upper", "true").lower() == "true"
    use_digits = request.GET.get("digits", "true").lower() == "true"
    use_special = request.GET.get("special", "true").lower() == "true"
    
    custom_words = request.GET.get("words", "").split(",")  # Custom words from user (comma-separated)
    
    characters = ""
    if use_lower:
        characters += string.ascii_lowercase
    if use_upper:
        characters += string.ascii_uppercase
    if use_digits:
        characters += string.digits
    if use_special:
        characters += string.punctuation

    if not characters:
        return JsonResponse({"error": "You must select at least one character type."}, status=400)
    
    password = "".join(random.choice(characters) for _ in range(length))

    # If custom words are provided, randomly insert them into the password
    if custom_words:
        random.shuffle(custom_words)  # Shuffle words
        word_insert_pos = random.randint(0, len(password))  # Random position in password
        password = password[:word_insert_pos] + "".join(custom_words) + password[word_insert_pos:]

    return JsonResponse({"password": password})


#------------------------- Secure File Sharing Tool-----------------------------------------
# Generate a key (Store this securely in a .env file in production)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)


def encrypt_file(file_data):
    """Encrypt the file content using Fernet encryption."""
    return cipher.encrypt(file_data)


def decrypt_file(encrypted_data):
    """Decrypt the encrypted file content."""
    return cipher.decrypt(encrypted_data)


@api_view(['POST'])
def upload_and_encrypt(request):
    """Handles file upload and encrypts it before saving."""
    if 'file' not in request.FILES:
        return Response({"error": "No file uploaded"}, status=400)

    file = request.FILES['file']
    encrypted_data = encrypt_file(file.read())

    secure_file = SecureFile()
    secure_file.file.save(file.name, ContentFile(encrypted_data))
    secure_file.save()

    return Response({"message": "File uploaded and encrypted successfully!"})


@api_view(['GET'])
def list_files(request):
    """Lists all stored files."""
    files = SecureFile.objects.all().values('id', 'file', 'uploaded_at')
    return Response(files)


@api_view(['GET'])
def download_decrypted(request, file_id):
    """Fetches an encrypted file, decrypts it, and returns its content."""
    try:
        file_obj = SecureFile.objects.get(id=file_id)
        with file_obj.file.open('rb') as f:
            encrypted_content = f.read()

        decrypted_data = decrypt_file(encrypted_content)

        response = HttpResponse(decrypted_data, content_type="application/octet-stream")
        response['Content-Disposition'] = f'attachment; filename="{file_obj.file.name}"'
        return response

    except SecureFile.DoesNotExist:
        return Response({"error": "File not found"}, status=404)

    except Exception as e:
        return Response({"error": str(e)}, status=500)
    
@api_view(['DELETE'])
def delete_file(request, file_id):
    """Deletes a file from the database and storage."""
    try:
        file_obj = SecureFile.objects.get(id=file_id)
        file_obj.file.delete()  # Delete file from storage
        file_obj.delete()  # Delete record from database
        return Response({"message": "File deleted successfully!"})
    except SecureFile.DoesNotExist:
        return Response({"error": "File not found"}, status=404)
    
#--------------------------Online Text Encryption and Decryption---------------------------------------
from django.http import JsonResponse
from django.db import models
from rest_framework.decorators import api_view
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

# 🔹 AES Encryption Configuration
AES_KEY = os.urandom(32)  # 256-bit key
AES_IV = os.urandom(16)   # 128-bit IV

# 🔹 Helper Functions
def encrypt_text(plain_text):
    """Encrypts text using AES encryption."""
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
    encryptor = cipher.encryptor()

    padded_text = plain_text.ljust(16 * ((len(plain_text) + 15) // 16))  # Padding
    encrypted_text = encryptor.update(padded_text.encode()) + encryptor.finalize()

    return base64.urlsafe_b64encode(AES_IV + encrypted_text).decode()

def decrypt_text(encrypted_text):
    """Decrypts AES-encrypted text."""
    encrypted_text_bytes = base64.urlsafe_b64decode(encrypted_text.encode())
    iv = encrypted_text_bytes[:16]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_text = decryptor.update(encrypted_text_bytes[16:]) + decryptor.finalize()
    return decrypted_text.decode().strip()

# 🔹 API Views
@api_view(['POST'])
def encrypt_message(request):
    """Encrypts the user-provided text and saves it."""
    text = request.data.get("text")
    if not text:
        return JsonResponse({"error": "No text provided"}, status=400)

    encrypted_text = encrypt_text(text)
    message = EncryptedMessage.objects.create(encrypted_text=encrypted_text)

    shareable_link = f"http://127.0.0.1:8000/api/decrypt/{message.id}/"
    
    return JsonResponse({
        "message": "Text encrypted successfully!",
        "message_id": message.id,
        "shareable_link": shareable_link
    }, status=201)

@api_view(['GET'])
def decrypt_message(request, message_id):
    """Decrypts and returns the encrypted message."""
    try:
        message = EncryptedMessage.objects.get(id=message_id)
        decrypted_text = decrypt_text(message.encrypted_text)

        return JsonResponse({"decrypted_text": decrypted_text})

    except EncryptedMessage.DoesNotExist:
        return JsonResponse({"error": "Message not found"}, status=404)


#------------------------------- Email Privacy Checker------------------------
import dns.resolver

# Function to Check Email Privacy (Previously in utils.py)
def check_email_privacy(email):
    domain = email.split("@")[-1]
    risks = []

    # Check SPF Record
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_record = [record.to_text() for record in answers if "spf" in record.to_text().lower()]
        if not spf_record:
            risks.append("No SPF record found. This can allow email spoofing.")
    except:
        risks.append("SPF check failed.")

    # Check DKIM Record
    try:
        dkim_selector = "default"
        dkim_domain = f"{dkim_selector}._domainkey.{domain}"
        dns.resolver.resolve(dkim_domain, "TXT")
    except:
        risks.append("No valid DKIM record found.")

    # Check DMARC Record
    try:
        dmarc_domain = f"_dmarc.{domain}"
        dns.resolver.resolve(dmarc_domain, "TXT")
    except:
        risks.append("No DMARC record found. Phishing attacks are more likely.")

    is_secure = len(risks) == 0
    return {"is_secure": is_secure, "risks": risks}

# API Endpoint
@api_view(['POST'])
def analyze_email(request):
    email = request.data.get("email")
    if not email or "@" not in email:
        return JsonResponse({"error": "Invalid email"}, status=400)

    result = check_email_privacy(email)
    email_check = EmailCheck.objects.create(email=email, is_secure=result["is_secure"], privacy_risks="\n".join(result["risks"]))

    return JsonResponse({
        "email": email,
        "is_secure": result["is_secure"],
        "privacy_risks": result["risks"]
    })


# ----------Metadata Stripper---------------------------------------------------------------------------
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.core.files.base import ContentFile
import os
from .models import UploadedFile
from pypdf import PdfReader, PdfWriter

def remove_metadata(file_path):
    try:
        reader = PdfReader(file_path)
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        # ✅ Remove metadata properly
        writer.add_metadata({})

        # ✅ Ensure "stripped" folder exists
        stripped_file_path = file_path.replace("uploads", "stripped")
        os.makedirs(os.path.dirname(stripped_file_path), exist_ok=True)

        with open(stripped_file_path, "wb") as out_f:
            writer.write(out_f)

        return stripped_file_path

    except Exception as e:
        print(f"Error processing PDF: {e}")
        return None

@api_view(['POST'])
def upload_and_strip_metadata(request):
    uploaded_file = request.FILES.get('file')
    if not uploaded_file:
        return Response({'error': 'No file uploaded'}, status=400)

    file_instance = UploadedFile.objects.create(file=uploaded_file)
    
    stripped_path = remove_metadata(file_instance.file.path)
    
    if not stripped_path or not os.path.exists(stripped_path):
        return Response({'error': 'Failed to process file'}, status=500)

    # Save the cleaned file
    with open(stripped_path, 'rb') as f:
        file_instance.stripped_file.save(os.path.basename(stripped_path), ContentFile(f.read()))

    # ✅ Debugging - Print file path
    print("Clean file saved at:", file_instance.stripped_file.url)

    return Response({'message': 'Metadata removed successfully', 'clean_file_url': file_instance.stripped_file.url})


# ---------------Phishing URL Scanner ---------------------------------------------------------------
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
import requests
from .models import ScannedURL

PHISHING_API = "https://phish.surf/api/v1/url/"

def check_url(url):
    """Check if the given URL is a phishing site."""
    validator = URLValidator()
    try:
        validator(url)
    except ValidationError:
        return {"error": "Invalid URL format"}

    try:
        response = requests.get(f"{PHISHING_API}?url={url}")
        data = response.json()
        return {"is_phishing": data.get("phishing", False)}
    except Exception as e:
        return {"error": str(e)}

@api_view(['POST'])
def scan_url(request):
    # Ensure request contains JSON data
    if not request.data:
        return Response({"error": "Invalid request, no data provided"}, status=400)

    # Extract URL from request
    url = request.data.get("url")
    
    if not url:
        return Response({"error": "URL is required"}, status=400)

    # Placeholder for phishing scan logic
    is_phishing = "phishing" in url  # Replace with actual logic

    return Response({"message": "Scan complete", "url": url, "is_phishing": is_phishing})

# -------------------VirusTotal API Integration ----------------------------------------------------------
import requests
from django.conf import settings
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.core.files.storage import default_storage

# VirusTotal API Key (Set this in settings.py or environment variables)
VIRUSTOTAL_API_KEY = settings.VIRUSTOTAL_API_KEY
BASE_VT_URL = "https://www.virustotal.com/api/v3"

@api_view(['POST'])
def scan_url(request):
    """ Submits a URL to VirusTotal for scanning. """
    url = request.data.get('url')
    if not url:
        return Response({'error': 'No URL provided'}, status=400)

    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    payload = {"url": url}

    response = requests.post(f"{BASE_VT_URL}/urls", headers=headers, data=payload)
    if response.status_code == 200:
        scan_data = response.json()
        analysis_id = scan_data["data"]["id"]
        return Response({"message": "Scan started", "analysis_id": analysis_id})
    else:
        return Response({"error": "Failed to submit URL for scanning"}, status=response.status_code)


@api_view(['GET'])
def fetch_scan_results(request, analysis_id):
    """ Fetches scan results using the analysis ID. """
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(f"{BASE_VT_URL}/analyses/{analysis_id}", headers=headers)

    if response.status_code == 200:
        scan_results = response.json()
        return Response(scan_results)
    else:
        return Response({"error": "Failed to fetch scan results"}, status=response.status_code)

# ---------------Ad Blocker recommendations------------------------------------

@api_view(['GET'])
def get_ad_blockers(request):
    ad_blockers = [
        {
            "name": "uBlock Origin",
            "description": "A free and open-source browser extension for content filtering and ad blocking.",
            "chrome_link": "https://chrome.google.com/webstore/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm",
            "firefox_link": "https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/",
        },
        {
            "name": "Privacy Badger",
            "description": "Automatically learns to block invisible trackers.",
            "chrome_link": "https://chrome.google.com/webstore/detail/privacy-badger/pkehgijcmpdhfbdbbnkijodmdjhbjlgp",
            "firefox_link": "https://addons.mozilla.org/en-US/firefox/addon/privacy-badger17/",
        },
        {
            "name": "Ghostery",
            "description": "Enhances privacy by blocking trackers and ads.",
            "chrome_link": "https://chrome.google.com/webstore/detail/ghostery/mnmldggghmokejdjljimmmchcgfhbmid",
            "firefox_link": "https://addons.mozilla.org/en-US/firefox/addon/ghostery/",
        },
    ]
    return Response(ad_blockers)

# ---------------- Whois and DNS lookup ----------------------------------------------------

from rest_framework.decorators import api_view
from rest_framework.response import Response
import whois
import dns.resolver

@api_view(['GET'])
def whois_lookup(request):
    domain = request.GET.get('domain')
    if not domain:
        return Response({'error': 'Domain parameter is required'}, status=400)
    try:
        domain_info = whois.whois(domain)
        return Response({'whois_data': domain_info.text})
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
def dns_lookup(request):
    domain = request.GET.get('domain')
    if not domain:
        return Response({'error': 'Domain parameter is required'}, status=400)
    
    try:
        records = {}
        for record_type in ['A', 'MX', 'TXT', 'CNAME']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                records[record_type] = []
        
        return Response({'dns_records': records})
    except Exception as e:
        return Response({'error': str(e)}, status=500)


