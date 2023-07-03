# Phishing Website Detector

This is a website for determining whether a website is legitimate or not
based on its URL features. An artificial neural network is trained
from the Web Page Phishing Detection dataset viewable through this
<a href="https://data.mendeley.com/datasets/c2gw7fy2j4/3">link</a>.

The website is created and served by Django. The Neural Network is made
with PyTorch and is saved as a .bin file which is loaded by the API whenever
predictions are needed.

## Setting Up

To set up the project, ensure you have the following prerequisite software
on your machine:

* Python 3.11.x
* Pipenv - dependency manager on top of pip and virtualenv.
  Execute `pip install pipenv` to install on your machine.

Then, to actually set up the project:

1. Clone this repository on your machine.
1. Open the project directory on your terminal
1. `pipenv install`
1. `pipenv shell`
1. `python manage.py migrate` - installs the database migrations to your
   local copy.
1. `python manage.py createsuperuser` - create a superuser account of
   the website.
1. `python manage.py runserver` - check if your setup is running.

## Development Workflow

To develop and push changes, then follow these steps:

1. Head to main branch. `git checkout main`
1. Branch out. `git branch your_branch`
1. Install database migrations. `python manage.py migrate`
1. Implement your changes to the source code.
1. Check your changes. `python manage.py runserver`
1. Perform a commit. Make sure you put a summary message.
   `git commit -m 'message'`
1. Push your branch. `git push origin your_branch`
1. On the Github page of this repo, create a pull request.
   Briefly discuss your changes. Ask for it to be merged to
   main. Should look like the following: `main <- your_branch`
