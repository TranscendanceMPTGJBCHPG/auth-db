import os
import jwt
import pytz
import uuid
import json
import pyotp
import qrcode
import base64
import logging
import requests

from io import BytesIO
from dotenv import load_dotenv
from oauth.models import UserProfile
from datetime import datetime, timedelta
from django.contrib.auth.models import User
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET


load_dotenv()
logger = logging.getLogger(__name__)

def generate_totp_secret():
    """Generates a secret for TOTP"""
    return pyotp.random_base32()

def generate_qr_code(username, secret):
    """Generates a QR code for Google Authenticator"""
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        username,
        issuer_name="Transcendence"
    )

    # Create QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    # Convert to image
    img_buffer = BytesIO()
    qr.make_image(fill_color="black", back_color="white").save(img_buffer, format='PNG')
    return base64.b64encode(img_buffer.getvalue()).decode()

def verify_totp(secret, token):
    """Verifies a TOTP token"""
    totp = pyotp.TOTP(secret)
    return totp.verify(token)


@require_POST
@csrf_exempt
def oauth_login(request):
    # logger.info("Starting oauth_login request")
    temp_jwt = request.POST.get('temp_token')

    if not temp_jwt:
        return JsonResponse({'error': 'Missing required parameter'}, status=400)

    try:
        # Verify temporary JWT
        SECRET_KEY = os.getenv('TEMPORARY_JWT_SECRET_KEY')
        try:
            jwt_data = jwt.decode(temp_jwt, SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'Token expired. Please authenticate again'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'error': 'Invalid token'}, status=401)

        user, created = User.objects.get_or_create(
            username=jwt_data['username'],
            defaults={'email': jwt_data['email']}
        )

        # Check 2FA status
        try:
            totp_secret = user.userprofile.totp_secret
            first_login_done = user.userprofile.first_login_done
            is_2fa_setup = bool(totp_secret)
        except:
            is_2fa_setup = False
            first_login_done = False
            totp_secret = None

        # Handle new user or no 2FA
        if first_login_done is False:
            if created or not is_2fa_setup:
                new_totp_secret = generate_totp_secret()
                if not hasattr(user, 'userprofile'):
                    UserProfile.objects.create(user=user, totp_secret=new_totp_secret, first_login_done=False)
                else:
                    user.userprofile.totp_secret = new_totp_secret 
                    user.userprofile.save()
            else:
                # Add this line to handle the case where first_login_done is False but user has 2FA setup
                new_totp_secret = user.userprofile.totp_secret

            qr_code = generate_qr_code(user.username, new_totp_secret)
            return JsonResponse({
                'status': 'setup_2fa',
                'qr_code': qr_code
            })

        # Existing user with 2FA
        return JsonResponse({
            'status': 'need_2fa'
        })

    except Exception as e:
        logger.error(f"Error in oauth_login: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@require_POST
@csrf_exempt
def verify_2fa(request):
    # logger.info("Starting 2FA verification")
    totp_token = request.POST.get('totp_token')
    temp_jwt = request.POST.get('temp_token')

    if not all([totp_token, temp_jwt]):
        return JsonResponse({'error': 'Missing required parameters'}, status=400)

    try:
        try:
            jwt_data = jwt.decode(temp_jwt, os.getenv('TEMPORARY_JWT_SECRET_KEY'), algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'Token expired. Please authenticate again'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'error': 'Invalid token'}, status=401)

        # Verify 2FA
        user = User.objects.get(username=jwt_data['username'])
        totp_secret = user.userprofile.totp_secret

        if not verify_totp(totp_secret, totp_token):
            logger.error(f"Invalid 2FA code: {totp_token}")
            return JsonResponse({'error': 'Invalid 2FA code'}, status=200)

        # Mark first login as done
        user.userprofile.first_login_done = True
        user.userprofile.save()

        # Generate new long-term JWT
        now = datetime.now(pytz.utc)
        expiration_time = now + timedelta(days=1)

        payload = {
            'username': user.username,
            'email': user.email,
            'image_link': jwt_data['image_link'],
            'exp': int(expiration_time.timestamp())
        }

        encoded_jwt = jwt.encode(payload, os.getenv('JWT_SECRET_KEY'), algorithm='HS256')
        return JsonResponse({'access_token': encoded_jwt}, status=200)

    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    except Exception as e:
        logger.error(f"Error in verify_2fa: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@require_GET
@csrf_exempt
def authfortytwo(request):
    code = request.GET.get('code')
    errorPage = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authentication failed</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
            <div class="text-center position-absolute top-50 start-50 translate-middle">
                <div class="text-danger">
                    <h1>Authentication failed</h1>
                </div>
                <div>
                    <h3>You are going to be redirected...</h3>
                </div>
            </div>
            <script>
                setTimeout(() => window.close(), 5000);
            </script>
        </body>
        </html>
    """
    htmlpage = """
       <!DOCTYPE html>
       <html>
       <head>
           <title>Authentication in progress...</title>
           <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
       </head>
       <body>
           <div class="text-center position-absolute top-50 start-50 translate-middle">
               <div class="text-success">
                   <div class="spinner-border" role="status">
                       <span class="visually-hidden">Loading...</span>
                   </div>
                   <h1>42 Login Successful!</h1>
               </div>
               <div>
                   <h3>You are going to be redirected...</h3>
               </div>
           </div>
           <script>
               setTimeout(() => window.close(), 3000);
           </script>
       </body>
       </html>
   """

    if not code:
        logging.error("No code")
        return HttpResponse(errorPage)

    try:
        host = request.META.get('HTTP_HOST')
        redirect_uri = f'https://{host}:7777/auth/authfortytwo'

        # logger.info(f"Redirect URI: {redirect_uri}")

        ft_token_data = {
            'grant_type': 'authorization_code',
            'client_id': os.getenv('VITE_CLIENT_ID'),
            'client_secret': os.getenv('VITE_CLIENT_SECRET'),
            'code': code,
            'redirect_uri': redirect_uri,
        }

        token_response = requests.post('https://api.intra.42.fr/oauth/token', data=ft_token_data)

        token_json = token_response.json()

        access_token = token_json.get('access_token')

        if not access_token:
            logging.error("No access token")
            return HttpResponse(errorPage)

        user_response = requests.get(
            'https://api.intra.42.fr/v2/me',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        user_json = user_response.json()

        if 'login' not in user_json or 'email' not in user_json:
            logging.error("No login or email")
            return HttpResponse(errorPage)

        user, created = User.objects.get_or_create(
            username=user_json['login'],
            defaults={'email': user_json['email']}
        )

        jwt_payload = {
            'username': user.username,
            'email': user.email,
            'image_link': user_json['image']['link'],
            'exp': datetime.now(pytz.utc) + timedelta(minutes=5)  # 5 minutes d'expiration
        }

        jwt_token = jwt.encode(
            jwt_payload,
            os.getenv('TEMPORARY_JWT_SECRET_KEY'),
            algorithm='HS256'
        )

        response = HttpResponse(htmlpage)
        response.set_cookie(
            'temp_token',
            jwt_token,
            max_age=5*60,  # 5 minutes en secondes
            secure=True,     # Garde HTTPS
            httponly=False,  # Permet l'accès JS
            samesite='Lax'  # Plus permissif pour localhost
        )

        return response

    except Exception as e:
        logging.error(f"Error in authfortytwo: {str(e)}")
        return HttpResponse(errorPage)