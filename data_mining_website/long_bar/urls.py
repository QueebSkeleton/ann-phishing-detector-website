from django.urls import path
from . import views

urlpatterns = [
    path('long_bar/', views.long_bar, name='long_bar'),
]