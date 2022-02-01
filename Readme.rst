Witness Angel Server
#################################

.. image:: https://travis-ci.com/WitnessAngel/witness-angel-trustee.svg?branch=master
    :target: https://travis-ci.com/WitnessAngel/witness-angel-trustee

This webservice exposes an Trustee API, so that Witness Angel devices may safely encrypt and sign their data in write-only mode.

This Django application exposes 3 webservices:

- WAGateway, which handles communication between WitnessAngel devices and their KeyGuardians
- WATrustee, which acts as a standlone key guardian delivering encryption keys and message signatures on demand
- WASupport, which logs application crashes for debigging purposes


Quick start
===================

The interpreter for `python3.7` (see `pyproject.toml` for full version) must be installed.

Instead of pip, we use `poetry <https://github.com/sdispater/poetry>`_ to manage dependencies.

Use `pip install poetry` to install poetry (or follow its official docs to install it system-wide).

Use `poetry install` to install python dependencies (poetry will create its own virtualenv if you don't have one activated).

Use `pytest` to launch unit-tests (its default arguments are in `setup.cfg`); you might need to add the "src/" directory of this repository to your pythonpath, until a better way to early-setup python paths is found. Use `poetry run pytest` instead, if poetry created its own virtualenv.

Use `bash ci.sh` to do a full checkup before committing or pushing your changes.

Use the `Black <https://black.readthedocs.io/en/stable/>`_ formatter to format your python code.

Use `python manage.py runserver`, or other standard `Django management commands <https://docs.djangoproject.com/en/dev/ref/django-admin/>`_, to interact with the server application.


