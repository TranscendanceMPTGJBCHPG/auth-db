import os
import jwt
import pytz
import logging

from dotenv import load_dotenv
from django.http import JsonResponse
from datetime import datetime, timedelta
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET


load_dotenv()
logger = logging.getLogger(__name__)

@require_GET
@csrf_exempt
def get_guest_token(request):
    logging.info("get_guest_token")

    now = datetime.now(pytz.utc)
    expiration_time = now + timedelta(days=1)
    payload = {
        'username': 'guest',
        'email': None,
        'image_link': None,
        'exp': int(expiration_time.timestamp())
    }

    encoded_jwt = jwt.encode(payload, os.getenv('JWT_SECRET_KEY'), algorithm='HS256')
    return JsonResponse({'access_token': encoded_jwt}, status=200)

