from django.contrib import admin
from django.http import HttpResponse
from django.urls import path, include


def health_check(request):
    return HttpResponse(status=200)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('oauth.urls')),
    path('health', health_check, name='health')
]
