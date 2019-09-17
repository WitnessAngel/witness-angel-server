import uuid

import pytest
from Crypto.Random import get_random_bytes
from django.db import IntegrityError
from django.test import Client
from jsonrpc.proxy import TestingServiceProxy

# MONKEY-PATCH django-jsonrpc package so that it uses Extended Json on proxy requests
from bson.json_util import dumps, loads
from jsonrpc import proxy

from wacryptolib.encryption import _encrypt_via_rsa_oaep
from wacryptolib.key_generation import load_asymmetric_key_from_pem_bytestring
from wacryptolib.signature import verify_signature
from waescrow.escrow_api import SqlKeyStorage

assert proxy.loads
proxy.loads = loads
assert proxy.dumps
proxy.dumps = dumps


def _get_jsonrpc_result(response_dict):
    assert isinstance(response_dict, dict)
    assert "error" not in response_dict
    return response_dict["result"]


def test_sql_key_storage(db):

    storage = SqlKeyStorage()

    keychain_uid1 = uuid.uuid4()
    keychain_uid2 = uuid.uuid4()
    keychain_uid_unexisting = uuid.uuid4()

    storage.set_keypair(keychain_uid=keychain_uid1, key_type="RSA", keypair=dict(a=2))
    storage.set_keypair(keychain_uid=keychain_uid2, key_type="RSA", keypair=dict(B="xyz"))
    storage.set_keypair(keychain_uid=keychain_uid1, key_type="DSA", keypair=dict(c=b"99"))
    storage.set_keypair(keychain_uid=keychain_uid2, key_type="DSA", keypair=dict(D=1.0))

    assert storage.get_keypair(keychain_uid=keychain_uid1, key_type="RSA") == dict(a=2)
    assert storage.get_keypair(keychain_uid=keychain_uid2, key_type="RSA") == dict(B="xyz")
    assert storage.get_keypair(keychain_uid=keychain_uid1, key_type="DSA") == dict(c=b"99")
    assert storage.get_keypair(keychain_uid=keychain_uid2, key_type="DSA") == dict(D=1.0)

    assert storage.get_keypair(keychain_uid=keychain_uid_unexisting, key_type="RSA") == None

    with pytest.raises(IntegrityError):  # Final tests, since it breaks current DB transaction
        storage.set_keypair(keychain_uid=keychain_uid1, key_type="RSA", keypair=dict(a=3))


def test_waescrow_escrow_api_workflow(db):

    escrow_proxy = TestingServiceProxy(
        client=Client(), service_url="/json/", version="2.0"
    )

    keychain_uid = uuid.uuid4()
    secret = get_random_bytes(101)

    public_key_pem = _get_jsonrpc_result(escrow_proxy.get_public_key(keychain_uid=keychain_uid, key_type="RSA"))
    public_key = load_asymmetric_key_from_pem_bytestring(
        key_pem=public_key_pem, key_type="RSA"
    )

    signature = _get_jsonrpc_result(escrow_proxy.get_message_signature(
            keychain_uid=keychain_uid, message=secret, key_type="RSA", signature_algo="PSS"
    ))
    verify_signature(
        message=secret, signature=signature, key=public_key, signature_algo="PSS"
    )

    signature["digest"] += b"xyz"
    with pytest.raises(ValueError, match="Incorrect signature"):
        verify_signature(
            message=secret, signature=signature, key=public_key, signature_algo="PSS"
        )

    cipherdict = _encrypt_via_rsa_oaep(plaintext=secret, key=public_key)

    decrypted = _get_jsonrpc_result(escrow_proxy.decrypt_with_private_key(
            keychain_uid=keychain_uid, key_type="RSA", encryption_algo="RSA_OAEP", cipherdict=cipherdict
    ))
    assert decrypted == secret

    cipherdict["digest_list"].append(b"aaabbbccc")
    with pytest.raises(ValueError, match="Ciphertext with incorrect length"):
        # Django test client reraises signalled exception
        escrow_proxy.decrypt_with_private_key(
                keychain_uid=keychain_uid, key_type="RSA", encryption_algo="RSA_OAEP", cipherdict=cipherdict
        )




