import os
import django

from dotenv import load_dotenv
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


load_dotenv()
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

User = get_user_model()

username = os.getenv('SUPERUSER_USERNAME')
email = os.getenv('SUPERUSER_EMAIL')
password = os.getenv('SUPERUSER_PASSWORD')

if not User.objects.filter(username=username).exists():
    User.objects.create_superuser(username=username, email=email, password=password)
    print('Superuser created successfully.')
    
else:
    print('Superuser already exists.')
