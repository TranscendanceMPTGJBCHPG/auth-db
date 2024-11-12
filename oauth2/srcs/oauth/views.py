import os
import jwt
import pytz
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
from django.views.decorators.http import require_POST


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
    logger.info("Starting oauth_login request")
    code = request.POST.get('code')
    totp_token = request.POST.get('totp_token')  # 2FA token if provided

    if code is None:
        logger.error("Failed: No authorization code provided")
        return JsonResponse({'error': 'Failed: No code provided'}, status=400)

    token_data = {
        'grant_type': 'authorization_code',
        'client_id': os.getenv('VITE_CLIENT_ID'),
        'client_secret': os.getenv('VITE_CLIENT_SECRET'),
        'code': code,
        'redirect_uri': os.getenv('VITE_REDIRECT_URI'),
    }

    try:
        # Get OAuth token
        logger.info("Attempting to obtain access token")
        token_response = requests.post('https://api.intra.42.fr/oauth/token', data=token_data)
        token_json = token_response.json()
        logger.debug(f"Token response: {token_json}")
        access_token = token_json.get('access_token')

        if access_token is None:
            logger.error("Failed: Access token not obtained")
            return JsonResponse({'error': 'Token not obtained'}, status=400)

        logger.info("Access token successfully obtained")

        # Get user data
        logger.info("Attempting to get user data")
        user_response = requests.get(
            'https://api.intra.42.fr/v2/me',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        user_json = user_response.json()
        logger.debug(f"User data received: {user_json}")

        if 'login' not in user_json or 'email' not in user_json:
            logger.error("Failed: Incomplete or invalid user data")
            return HttpResponse('Failure: User data not obtained', status=400)

        # Get or create user
        logger.info(f"Attempting to get/create user: {user_json['login']}")
        user, created = User.objects.get_or_create(
            username=user_json['login'],
            defaults={
                'email': user_json['email'],
            }
        )

        # Check if user has already set up 2FA
        try:
            totp_secret = user.userprofile.totp_secret
            is_2fa_setup = bool(totp_secret)
            logger.info("2FA status checked successfully")

        except:
            logger.info("No 2FA setup found for user")
            is_2fa_setup = False
            totp_secret = None

        # Case 1: New user or 2FA not configured
        if created or not is_2fa_setup:
            logger.info("Setting up new 2FA configuration")
            # Generate new TOTP secret
            new_totp_secret = generate_totp_secret()

            # Create or update user profile
            if not hasattr(user, 'userprofile'):
                logger.info("Creating new user profile with 2FA settings")
                UserProfile.objects.create(
                    user=user,
                    totp_secret=new_totp_secret
                )

            else:
                logger.info("Updating existing user profile with new 2FA settings")
                user.userprofile.totp_secret = new_totp_secret
                user.userprofile.save()

            # Generate QR code for Google Authenticator
            qr_code = generate_qr_code(user.username, new_totp_secret)
            logger.info("2FA QR code generated successfully")

            return JsonResponse({
                'status': 'setup_2fa',
                'qr_code': qr_code,
                'message': 'Please set up Google Authenticator with the provided QR code'
            })

        # Case 2: Existing user with 2FA already configured
        if not totp_token:
            logger.info("2FA token required for existing user")
            return JsonResponse({
                'status': 'need_2fa',
                'qr_code': generate_qr_code(user.username, user.userprofile.totp_secret),
                'message': 'Please provide a 2FA code'
            })

        # Verify TOTP token
        logger.info("Verifying 2FA token")

        if not verify_totp(totp_secret, totp_token):
            logger.error("Failed: Invalid 2FA code")
            return JsonResponse({
                'error': 'Invalid 2FA code'
            }, status=400)

        logger.info("2FA verification successful")

        # Generate JWT after successful 2FA
        logger.info("Generating JWT")
        SECRET_KEY = os.getenv('JWT_SECRET_KEY')
        now = datetime.now(pytz.utc)
        expiration_time = now + timedelta(days=1)

        payload = {
            'username': user.username,
            'email': user.email,
            'game_access': 1,
            'image_link': user_json['image']['link'],
            'exp': int(expiration_time.timestamp())
        }

        logger.debug(f"Prepared JWT payload: {payload}")
        encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        logger.info("JWT successfully generated after 2FA validation")

        return JsonResponse({'access_token': encoded_jwt}, status=200)

    except requests.exceptions.RequestException as e:
        logger.error(f"API request error: {str(e)}")
        return JsonResponse({'error': 'API request failed'}, status=500)

    except jwt.PyJWTError as e:
        logger.error(f"JWT generation error: {str(e)}")
        return JsonResponse({'error': 'JWT generation failed'}, status=500)

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return JsonResponse({'error': 'Unexpected error occurred'}, status=500)
