
import random
import requests

import pytest


def test_waserver_wsgi_application(db):
    from waserver.wsgi import application

    with pytest.raises(KeyError, match="REQUEST_METHOD"):
        application(environ={}, start_response=lambda *args, **kwargs: None)



def test_jsonrpc_invalid_http_get_request(live_server):
    jsonrpc_url = live_server.url + random.choice(["/gateway/jsonrpc/", "/trustee/jsonrpc/"])

    response = requests.get(jsonrpc_url)
    assert response.headers["Content-Type"] == "application/json"
    assert response.json() == \
           {'error': {'code': {'$numberInt': '-32600'},
                      'data': None,
                      'message': 'InvalidRequestError: The method you are trying to access is not available by GET requests',
                      'name': 'InvalidRequestError'}, 'id': None}
