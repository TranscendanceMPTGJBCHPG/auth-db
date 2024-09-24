#!/bin/bash
set -e

sleep 10

python manage.py makemigrations
python manage.py migrate
python create_superuser.py
exec gunicorn --config gunicorn_config.py core.wsgi:application
