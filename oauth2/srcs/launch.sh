#!/bin/bash
set -e

sleep 20

python manage.py makemigrations
python manage.py makemigrations oauth
python manage.py migrate
python create_superuser.py
exec gunicorn --config gunicorn_config.py core.wsgi:application
