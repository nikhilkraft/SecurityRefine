from django.urls import path
from .views import analyze_email, check_password_strength, delete_file, dns_lookup, fetch_scan_results, get_ad_blockers, scan_url, whois_lookup
from .views import download_decrypted, list_files, upload_and_encrypt
from .views import generate_password
from .views import encrypt_message,decrypt_message
from .views import upload_and_strip_metadata

urlpatterns = [
    #password strength checker
    path('password-strength/', check_password_strength, name="password-strength"),
    
    #password generator
    path('generate-password/', generate_password, name="generate-password"),
    
    # secure file sharing
    path('upload/', upload_and_encrypt, name="upload"),
    path('files/', list_files, name="list_files"),
    path('download/<int:file_id>/', download_decrypted, name="download"),
    path('delete/<int:file_id>/',delete_file,name='delete_file'),
    
    #online text encryption and decryption
    path('encrypt/', encrypt_message, name='encrypt-message'),
    path('decrypt/<int:message_id>/', decrypt_message, name='decrypt-message'),
    
    # email privacy checker
    path('analyze/', analyze_email, name='analyze-email'),
    
    # metadata stripper
    path('strip-metadata/', upload_and_strip_metadata, name='strip-metadata'),
    
    # phishing url scanner
    path("scan-url/", scan_url, name="scan-url"),
    
    # virustotal api integration
    path('scan-url/', scan_url, name='scan-url'),
    path('scan-results/<str:analysis_id>/', fetch_scan_results, name='fetch-scan-results'),
    
    # Ad blocker recommendations
    path('ad-blockers/', get_ad_blockers, name='get_ad_blockers'),
    
    # Whoisdns lookup
    path('whoislookup/',whois_lookup,name='whois-lookup'),
    path('dnslookup/',dns_lookup,name='dns-lookup'),
    


]
