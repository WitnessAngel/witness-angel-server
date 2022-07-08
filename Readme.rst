Witness Angel Server
#################################

This Django application exposes 3 webservices:

- WAGateway, which handles communication between WitnessAngel devices and their KeyGuardians
- WATrustee, which acts as a standlone key guardian delivering encryption keys and message signatures on demand
- WASupport, which logs application crashes for debigging purposes


Quick start
===================

The interpreter for `python3.7+` (see `pyproject.toml` for compatible version) must be installed.

Instead of pip, we use `poetry <https://github.com/sdispater/poetry>`_ to manage dependencies.

Use `pip install poetry` to install poetry (or follow its official docs to install it system-wide).

Use `poetry install` to install python dependencies (poetry will create its own virtualenv if you don't have one activated).

Use `settings.ini.template` as a basis to create your own `settings.ini` at repository root.

Use `pytest` to launch unit-tests (its default arguments are in `setup.cfg`). If poetry created its own virtualenv, use `poetry run pytest` instead.

Use `bash ci.sh` to do a full checkup before committing or pushing your changes.

Use the `Black <https://black.readthedocs.io/en/stable/>`_ formatter to format your python code (max line length: 120 characters).

Use `python manage.py runserver`, or other standard `Django management commands <https://docs.djangoproject.com/en/dev/ref/django-admin/>`_, to interact with the server application.
