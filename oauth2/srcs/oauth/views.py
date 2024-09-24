import os
import jwt
import pytz
import requests

from dotenv import load_dotenv
from datetime import datetime, timedelta
from django.contrib.auth.models import User
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

load_dotenv()

@require_POST
@csrf_exempt
def oauth_login(request):
    code = request.POST.get('code')

    if code is None:
        return JsonResponse({'error': 'Échec : Code non fourni'}, status=400)

    token_data = {
        'grant_type': 'authorization_code',
        'client_id': os.getenv('CLIENT_ID'),
        'client_secret': os.getenv('CLIENT_SECRET'),
        'code': code,
        'redirect_uri': os.getenv('REDIRECT_URI'),
    }
    token_response = requests.post('https://api.intra.42.fr/oauth/token', data=token_data)
    token_json = token_response.json()
    access_token = token_json.get('access_token')

    if access_token is None:
        return JsonResponse({'error': 'Token not obtained'}, status=400)

    user_response = requests.get('https://api.intra.42.fr/v2/me',
                                 headers={'Authorization': f'Bearer {access_token}'})
    user_json = user_response.json()

    if 'login' not in user_json or 'email' not in user_json:
        return HttpResponse('Failure: User data not obtained', status=400)

    user, created = User.objects.get_or_create(
        username=user_json['login'],
        defaults={
            'email': user_json['email'],
        },
    )

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
    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    return JsonResponse({'access_token': encoded_jwt}, status=200)
