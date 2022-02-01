from unittest.mock import patch
from uuid import UUID

import random
import requests

import pytest
from jsonrpc_requests import TransportError

from wacryptolib.exceptions import KeystoreDoesNotExist
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler


def test_waserver_wsgi_application(db):
    from waserver.wsgi import application

    with pytest.raises(KeyError, match="REQUEST_METHOD"):
        application(environ={}, start_response=lambda *args, **kwargs: None)


def test_robots_txt(client):
    response = client.get("/robots.txt")
    assert response.status_code == 200
    assert "User-agent" in response.content.decode("utf8")


def test_jsonrpc_invalid_http_get_request(live_server):
    jsonrpc_url = live_server.url + random.choice(["/gateway/jsonrpc/", "/trustee/jsonrpc/"])

    response = requests.get(jsonrpc_url)
    assert response.headers["Content-Type"] == "application/json"
    assert response.json() == \
           {'error': {'code': {'$numberInt': '-32600'},
                      'data': None,
                      'message': 'InvalidRequestError: The method you are trying to access is not available by GET requests',
                      'name': 'InvalidRequestError'}, 'id': None}


def test_waserver_abnormal_error_masking(live_server):
    jsonrpc_url = live_server.url + "/gateway/jsonrpc/"

    gateway_proxy = JsonRpcProxy(
        url=jsonrpc_url, response_error_handler=status_slugs_response_error_handler)

    keystore_uid = UUID("cac682a8-809f-4de5-bbfd-72b533a37a21")

    with pytest.raises(KeystoreDoesNotExist):  # Error well translated
        gateway_proxy.get_public_authenticator(keystore_uid=keystore_uid)

    # Patch the IMPORTED callable of view.py!
    with patch("waserver.apps.wagateway.views.get_public_authenticator", side_effect=KeyError("wrong key ABC")):

        with pytest.raises(TransportError):  # Server error NOT translated!
            gateway_proxy.get_public_authenticator(keystore_uid=keystore_uid)

