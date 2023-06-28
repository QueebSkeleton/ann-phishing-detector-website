from django.shortcuts import render
from django.http import HttpResponse
from django.template import loader

# Create your views here.

def long_bar(request):
    template = loader.get_template('long_bar.html')
    return HttpResponse(template.render())