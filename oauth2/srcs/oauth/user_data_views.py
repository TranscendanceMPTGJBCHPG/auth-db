import os
import jwt
import logging

from dotenv import load_dotenv
from django.db import transaction
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET


load_dotenv()
logger = logging.getLogger(__name__)

@require_GET
@csrf_exempt
def get_user_win_counter(request):
    jwt_token = request.GET.get('token')

    if not jwt_token:
        return JsonResponse({'error': 'Missing required parameter'}, status=400)

    try:
        jwt_data = jwt.decode(jwt_token, os.getenv('JWT_SECRET_KEY'), algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'Token expired. Please authenticate again'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'error': 'Invalid token'}, status=401)

    username = jwt_data.get('username')
    if not username:
        return JsonResponse({'error': 'Missing username'}, status=400)

    try:
        user = User.objects.get(username=username)
        return JsonResponse({'win_counter': user.userprofile.win_counter}, status=200)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    except Exception as e:
        logger.error(f"Error in get_user_win_counter: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@require_GET
@csrf_exempt
def get_user_goal_counter(request):
    jwt_token = request.GET.get('token')

    if not jwt_token:
        return JsonResponse({'error': 'Missing required parameter'}, status=400)

    try:
        jwt_data = jwt.decode(jwt_token, os.getenv('JWT_SECRET_KEY'), algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'Token expired. Please authenticate again'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'error': 'Invalid token'}, status=401)

    username = jwt_data.get('username')
    if not username:
        return JsonResponse({'error': 'Missing username'}, status=400)

    try:
        user = User.objects.get(username=username)
        return JsonResponse({'goal_counter': user.userprofile.goal_counter}, status=200)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    except Exception as e:
        logger.error(f"Error in get_user_goal_counter: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)



@require_POST
@csrf_exempt
def increment_user_win_counter(request):
    jwt_token = request.POST.get('token')
    if not jwt_token:
        return JsonResponse({'error': 'Missing required parameter'}, status=400)
    
    try:
        jwt_data = jwt.decode(jwt_token, os.getenv('JWT_SECRET_KEY'), algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'Token expired. Please authenticate again'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'error': 'Invalid token'}, status=401)
        
    username = jwt_data.get('username')
    if not username:
        return JsonResponse({'error': 'Missing username'}, status=400)
        
    try:
        with transaction.atomic():
            user = User.objects.select_for_update().get(username=username)
            user.userprofile.win_counter += 1
            user.userprofile.save()
            
        return JsonResponse({
            'success': True,
            'win_counter': user.userprofile.win_counter
        }, status=200)
        
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    except Exception as e:
        logger.error(f"Error in increment_user_win_counter: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@require_POST
@csrf_exempt
def increment_user_goal_counter(request):
    jwt_token = request.POST.get('token')
    if not jwt_token:
        return JsonResponse({'error': 'Missing required parameter'}, status=400)
    
    try:
        jwt_data = jwt.decode(jwt_token, os.getenv('JWT_SECRET_KEY'), algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'Token expired. Please authenticate again'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'error': 'Invalid token'}, status=401)
        
    username = jwt_data.get('username')
    if not username:
        return JsonResponse({'error': 'Missing username'}, status=400)
        
    try:
        with transaction.atomic():
            user = User.objects.select_for_update().get(username=username)
            user.userprofile.goal_counter += 1
            user.userprofile.save()
            
        return JsonResponse({
            'success': True,
            'goal_counter': user.userprofile.goal_counter
        }, status=200)
        
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    except Exception as e:
        logger.error(f"Error in increment_user_goal_counter: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@require_POST
@csrf_exempt
def reset(request):
    jwt_token = request.POST.get('token')

    if not jwt_token:
        return JsonResponse({'error': 'Missing required parameter'}, status=400)

    try:
        jwt_data = jwt.decode(jwt_token, os.getenv('JWT_SECRET_KEY'), algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'Token expired. Please authenticate again'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'error': 'Invalid token'}, status=401)
    username = jwt_data.get('username')
    if not username:
        return JsonResponse({'error': 'Missing username'}, status=400)

    try:
        user = User.objects.get(username=username)
        user.delete()
        return JsonResponse({'status': 'success'}, status=200)
    except User.DoesNotExist:
        logger.error(f"User not found for deletion: {username}")
        return JsonResponse({'error': 'User not found'}, status=404)
    except Exception as e:
        logger.error(f"Error in reset: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)
