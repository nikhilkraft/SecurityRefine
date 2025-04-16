from django.contrib.auth.hashers import check_password, make_password
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
from .models import UserRegistrationModel


@api_view(['POST'])
def user_register(request):
    required_fields = ['firstname', 'lastname', 'email', 'password']

    # Validate required fields
    for field in required_fields:
        if field not in request.data or not request.data[field].strip():
            return Response({"error": f"{field.capitalize()} is required"}, status=status.HTTP_400_BAD_REQUEST)

    firstname = request.data['firstname'].strip()
    lastname = request.data['lastname'].strip()
    email = request.data['email'].strip().lower()
    password = request.data['password']

    # ✅ Check for duplicate email
    if UserRegistrationModel.objects.filter(email=email).exists():
        return Response({"error": "Email is already registered."}, status=status.HTTP_400_BAD_REQUEST)

    # 🔐 Hash password securely
    hashed_password = make_password(password)

    # ✅ Create user without enforcing unique firstname/lastname
    user = UserRegistrationModel.objects.create(
        firstname=firstname,
        lastname=lastname,
        email=email,
        password=hashed_password
    )

    return Response({"message": "User registered successfully!"}, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def user_login(request):
    if 'email' not in request.data or 'password' not in request.data:
        return Response({"error": "Email and password are required"}, status=status.HTTP_400_BAD_REQUEST)
    
    email = request.data['email']
    password = request.data['password']
    
    try:
        user = UserRegistrationModel.objects.get(email=email)
        
        # Verify password
        if check_password(password, user.password):
            request.session['id'] = user.id
            request.session['loggeduser'] = f"{user.firstname} {user.lastname}"
            request.session['email'] = user.email
            
            return Response(
                {"message": "Login successful", "user": f"{user.firstname} {user.lastname}"},
                status=status.HTTP_200_OK
            )
        
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
    
    except UserRegistrationModel.DoesNotExist:
        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
