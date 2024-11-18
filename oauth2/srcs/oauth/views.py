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

    if not code:
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
        token_response = requests.post('https://api.intra.42.fr/oauth/token', data=token_data)
        token_json = token_response.json()
        access_token = token_json.get('access_token')

        if not access_token:
            logger.error("Failed: Access token not obtained")
            return JsonResponse({'error': 'Token not obtained'}, status=400)

        # Get user data
        user_response = requests.get(
            'https://api.intra.42.fr/v2/me',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        user_json = user_response.json()

        if 'login' not in user_json or 'email' not in user_json:
            logger.error("Failed: Incomplete user data")
            return JsonResponse({'error': 'User data not obtained'}, status=400)

        # Get or create user
        user, created = User.objects.get_or_create(
            username=user_json['login'],
            defaults={'email': user_json['email']}
        )

        # Generate a unique session token
        oauth_session_token = secrets.token_urlsafe(32)
        
        # Store OAuth validation data in session with expiration
        request.session[f'oauth_validated_{oauth_session_token}'] = {
            'username': user.username,
            'email': user.email,
            'image_link': user_json['image']['link'],
            'timestamp': datetime.now(pytz.utc).timestamp(),
            'validated': True
        }
        
        # Set session expiration to 5 minutes
        request.session.set_expiry(300)

        # Check 2FA status
        try:
            totp_secret = user.userprofile.totp_secret
            is_2fa_setup = bool(totp_secret)
        except:
            is_2fa_setup = False
            totp_secret = None

        # Handle new user or no 2FA
        if created or not is_2fa_setup:
            new_totp_secret = generate_totp_secret()
            
            if not hasattr(user, 'userprofile'):
                UserProfile.objects.create(user=user, totp_secret=new_totp_secret)
            else:
                user.userprofile.totp_secret = new_totp_secret
                user.userprofile.save()

            qr_code = generate_qr_code(user.username, new_totp_secret)
            return JsonResponse({
                'status': 'setup_2fa',
                'qr_code': qr_code,
                'session_token': oauth_session_token,
                'user_data': {
                    'username': user.username,
                    'email': user.email,
                    'image_link': user_json['image']['link']
                }
            })

        # Existing user with 2FA
        return JsonResponse({
            'status': 'need_2fa',
            'session_token': oauth_session_token,
            'user_data': {
                'username': user.username,
                'email': user.email,
                'image_link': user_json['image']['link']
            }
        })

    except Exception as e:
        logger.error(f"Error in oauth_login: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@require_POST
@csrf_exempt
def verify_2fa(request):
    logger.info("Starting 2FA verification")
    username = request.POST.get('username')
    totp_token = request.POST.get('totp_token')
    oauth_session_token = request.POST.get('session_token')

    if not all([username, totp_token, oauth_session_token]):
        return JsonResponse({'error': 'Missing required parameters'}, status=400)

    # Verify OAuth session
    session_key = f'oauth_validated_{oauth_session_token}'
    oauth_data = request.session.get(session_key)
    
    if not oauth_data or not oauth_data.get('validated'):
        logger.error("No valid OAuth session found")
        return JsonResponse({'error': 'Invalid session. Please authenticate through OAuth first'}, status=401)

    # Verify username matches OAuth session
    if oauth_data['username'] != username:
        logger.error("Username mismatch with OAuth session")
        return JsonResponse({'error': 'Invalid session data'}, status=401)

    # Check session expiration (5 minutes)
    session_timestamp = oauth_data.get('timestamp')
    if not session_timestamp or (datetime.now(pytz.utc).timestamp() - session_timestamp) > 300:
        # Clean up expired session
        request.session.pop(session_key, None)
        return JsonResponse({'error': 'Session expired. Please authenticate again'}, status=401)

    try:
        user = User.objects.get(username=username)
        totp_secret = user.userprofile.totp_secret

        if not verify_totp(totp_secret, totp_token):
            logger.error(f"Invalid 2FA code: {totp_token}")
            return JsonResponse({'error': 'Invalid 2FA code'}, status=400)

        # Clean up the session after successful verification
        request.session.pop(session_key, None)

        # Generate JWT
        SECRET_KEY = os.getenv('JWT_SECRET_KEY')
        now = datetime.now(pytz.utc)
        expiration_time = now + timedelta(days=1)

        payload = {
            'username': user.username,
            'email': user.email,
            'game_access': 1,
            'image_link': oauth_data['image_link'],
            'exp': int(expiration_time.timestamp())
        }

        encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return JsonResponse({'access_token': encoded_jwt}, status=200)

    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    except Exception as e:
        logger.error(f"Error in verify_2fa: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)