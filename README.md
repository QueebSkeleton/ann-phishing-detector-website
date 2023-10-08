<a name="readme-top"></a>

<!-- PROJECT SHIELDS -->
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]

<div align="center">
  <h3 align="center">Neural Network Phishing Website Detector</h3>
  <p align="center">
    For deteching phishing websites in both a URL and content-based manner.
  </p>
</div>

## About the Project

This website embeds a website phishing detector neural network model as an exposed
API on the backend. A request is to be made to this API which loads the
embedded model binary, then the results of the inference is returned as JSON.

The model extracts features both from the Uniform Resource Locator itself and
the website contents via an HTTP request.

The software is submitted in partial fulfillment of the requirements for the course
**CS Elective 4 - Data Mining** under the *Computer Science* program of the
Polytechnic University of the Philippines.

## Todo for the Project

- [x] Main Frontend
- [x] Train and deploy ANN model with the project as a binary
- [ ] Easier training facility with Django Admin

## Built With

This website is built with the following technologies:

[![Python][Python-shield]][Python-docs]
[![Django][Django-shield]][Django-docs]
[![PyTorch][PyTorch-shield]][PyTorch-docs]

## Installation

Install the following beforehand:

1. Python 3.x
1. pipenv - `pip install pipenv`

To run on your development machine, do the following steps:

1. Clone the repo - `git clone https://github.com/QueebSkeleton/ann-phishing-detector-website.git`
1. Open the project directory on your terminal.
1. Install dependencies - `pipenv install`
1. Run a shell with the created virtualenv - `pipenv shell`
1. Run database migrations - `python manage.py migrate`
1. Create an admin account for the website - `python manage.py createsuperuser`
then follow the instructions.
1. Run the dev server - `python manage.py runserver`

Then, the instance will now run on your local machine. Endpoints are:

1. `localhost:8000` - the index page of the application.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- Markdown Links & Images -->
[stars-shield]: https://img.shields.io/github/stars/QueebSkeleton/ann-phishing-detector-website?style=for-the-badge
[stars-url]: https://github.com/QueebSkeleton/ann-phishing-detector-website/stargazers
[issues-shield]: https://img.shields.io/github/issues/QueebSkeleton/ann-phishing-detector-website?style=for-the-badge
[issues-url]: https://github.com/QueebSkeleton/ann-phishing-detector-website/issues

[Python-shield]: https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54
[Python-docs]: https://www.python.org/
[Django-shield]: https://img.shields.io/badge/django-%23092E20.svg?style=for-the-badge&logo=django&logoColor=white
[Django-docs]: https://www.djangoproject.com/
[PyTorch-shield]: https://img.shields.io/badge/PyTorch-%23EE4C2C.svg?style=for-the-badge&logo=PyTorch&logoColor=white
[PyTorch-docs]: https://pytorch.org/

