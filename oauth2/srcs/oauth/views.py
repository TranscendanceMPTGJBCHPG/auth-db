import os
import jwt
import pytz
import logging
import requests

from dotenv import load_dotenv
from datetime import datetime, timedelta
from django.contrib.auth.models import User
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST


load_dotenv()
logger = logging.getLogger(__name__)

@require_POST
@csrf_exempt
def oauth_login(request):
    logger.info("Début de la requête oauth_login")
    code = request.POST.get('code')
    logger.debug(f"Code d'autorisation reçu: {code}")

    if code is None:
        logger.error("Échec : Aucun code d'autorisation fourni")
        return JsonResponse({'error': 'Échec : Code non fourni'}, status=400)

    token_data = {
        'grant_type': 'authorization_code',
        'client_id': os.getenv('CLIENT_ID'),
        'client_secret': os.getenv('CLIENT_SECRET'),
        'code': code,
        'redirect_uri': os.getenv('REDIRECT_URI'),
    }
    logger.debug(f"Données de la requête token: {token_data}")

    try:
        logger.info("Tentative d'obtention du token d'accès")
        token_response = requests.post('https://api.intra.42.fr/oauth/token', data=token_data)
        token_json = token_response.json()
        logger.debug(f"Réponse du token: {token_json}")
        access_token = token_json.get('access_token')

        if access_token is None:
            logger.error("Échec : Token d'accès non obtenu")
            return JsonResponse({'error': 'Token not obtained'}, status=400)

        logger.info("Token d'accès obtenu avec succès")
        logger.info("Tentative d'obtention des données utilisateur")
        user_response = requests.get(
            'https://api.intra.42.fr/v2/me',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        user_json = user_response.json()
        logger.debug(f"Données utilisateur reçues: {user_json}")

        if 'login' not in user_json or 'email' not in user_json:
            logger.error("Échec : Données utilisateur incomplètes ou invalides")
            return HttpResponse('Failure: User data not obtained', status=400)

        logger.info(f"Tentative de création/récupération de l'utilisateur: {user_json['login']}")
        user, created = User.objects.get_or_create(
            username=user_json['login'],
            defaults={
                'email': user_json['email'],
            },
        )
        if created:
            logger.info(f"Nouvel utilisateur créé: {user.username}")

        else:
            logger.info(f"Utilisateur existant récupéré: {user.username}")

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
        logger.debug(f"Payload JWT préparé: {payload}")
        encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        logger.info("JWT généré avec succès")
        return JsonResponse({'access_token': encoded_jwt}, status=200)

    except requests.exceptions.RequestException as e:
        logger.error(f"Erreur lors de la requête API: {str(e)}")
        return JsonResponse({'error': 'API request failed'}, status=500)

    except jwt.PyJWTError as e:
        logger.error(f"Erreur lors de la génération du JWT: {str(e)}")
        return JsonResponse({'error': 'JWT generation failed'}, status=500)

    except Exception as e:
        logger.error(f"Erreur inattendue: {str(e)}")
        return JsonResponse({'error': 'Unexpected error occurred'}, status=500)