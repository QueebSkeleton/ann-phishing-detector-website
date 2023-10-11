from django.shortcuts import render
from django.http.response import JsonResponse

import torch
import dill

from .utils.feature_extractor import extract_features
from .utils.feature_description import DESCRIPTIONS

def index(request):
    return render(request, "detector/index.html", {})


def predict(request):
    # Load the model, scaler
    import os
    module_dir = os.path.dirname(__file__)
    with open(os.path.join(module_dir, "inferencemodel_binaries/model.dill"), "rb") as model_file:
        phishing_model = dill.load(model_file)
    with open(os.path.join(module_dir, "inferencemodel_binaries/input_scaler.dill"), "rb") as input_scaler_file:
        input_scaler = dill.load(input_scaler_file)

    # Get the URL to predict from the request
    url = request.GET['inputURL']
    url_features = extract_features(url)
    input_to_model = torch.from_numpy(input_scaler.transform([list(url_features.values())])).to(torch.float32)
    # Feed forward to ANN, get classification
    with torch.no_grad():
        phishing_model.eval()
        is_phishing = (torch.sigmoid(phishing_model(input_to_model)).reshape(-1) >= 0.5)[0].item()
    # FOR OUTPUT: transform to boolean the appropriate features
    FEATURES_AS_BOOL = ['http_in_path', 'https_token', 'punycode', 'port',
                        'tld_in_path', 'tld_in_subdomain', 'shortening_service',
                        'path_extension', 'domain_in_brand', 'brand_in_subdomain',
                        'brand_in_path', 'suspicious_tld']
    for FEATURE in FEATURES_AS_BOOL:
        url_features[FEATURE] = bool(url_features[FEATURE])
    return JsonResponse({
        'is_phishing': is_phishing,
        'extracted_features': url_features,
        'feature_descriptions': DESCRIPTIONS
    })
