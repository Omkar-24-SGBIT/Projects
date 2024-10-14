from unicodedata import name
from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from sklearn.ensemble import RandomForestClassifier
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('check_website/',views.check_website,name='check_website'),
    
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
