import uuid
from datetime import timedelta

import pytest
from Crypto.Random import get_random_bytes
from django.db import IntegrityError
from django.test import Client
from django.utils import timezone
from freezegun import freeze_time
from jsonrpc.proxy import TestingServiceProxy

# MONKEY-PATCH django-jsonrpc package so that it uses Extended Json on proxy requests
from bson.json_util import dumps, loads
from jsonrpc import proxy

from wacryptolib.encryption import _encrypt_via_rsa_oaep
from wacryptolib.key_generation import load_asymmetric_key_from_pem_bytestring
from wacryptolib.signature import verify_message_signature
from waescrow import escrow_api
from waescrow.escrow_api import SqlKeyStorage
from waescrow.models import EscrowKeypair

assert proxy.loads
proxy.loads = loads
assert proxy.dumps
proxy.dumps = dumps


def _get_jsonrpc_result(response_dict):
    assert isinstance(response_dict, dict)
    assert "error" not in response_dict
    return response_dict["result"]


def test_sql_key_storage(db):

    key_storage = SqlKeyStorage()

    keychain_uid1 = uuid.uuid4()
    keychain_uid2 = uuid.uuid4()
    keychain_uid_unexisting = uuid.uuid4()

    key_storage.set_keys(keychain_uid=keychain_uid1, key_type="RSA", public_key=b"pubkey", private_key=b"privkey")
    key_storage.set_keys(keychain_uid=keychain_uid2, key_type="RSA", public_key=b"pubkey2", private_key=b"privkey2")
    key_storage.set_keys(keychain_uid=keychain_uid1, key_type="DSA", public_key=b"pubkey3", private_key=b"privkey3")
    key_storage.set_keys(keychain_uid=keychain_uid2, key_type="DSA", public_key=b"pubkey4", private_key=b"privkey4")

    assert key_storage.get_public_key(keychain_uid=keychain_uid1, key_type="RSA") == b"pubkey"
    assert key_storage.get_private_key(keychain_uid=keychain_uid1, key_type="RSA") == b"privkey"

    assert key_storage.get_public_key(keychain_uid=keychain_uid2, key_type="RSA") == b"pubkey2"
    assert key_storage.get_private_key(keychain_uid=keychain_uid2, key_type="RSA") == b"privkey2"

    assert key_storage.get_public_key(keychain_uid=keychain_uid1, key_type="DSA") == b"pubkey3"
    assert key_storage.get_private_key(keychain_uid=keychain_uid1, key_type="DSA") == b"privkey3"

    assert key_storage.get_public_key(keychain_uid=keychain_uid2, key_type="DSA") == b"pubkey4"
    assert key_storage.get_private_key(keychain_uid=keychain_uid2, key_type="DSA") == b"privkey4"

    assert key_storage.get_public_key(keychain_uid=keychain_uid_unexisting, key_type="RSA") == None
    assert key_storage.get_private_key(keychain_uid=keychain_uid_unexisting, key_type="RSA") == None

    with pytest.raises(IntegrityError):  # Final tests, since it breaks current DB transaction
        key_storage.set_keys(keychain_uid=keychain_uid1, key_type="RSA", public_key=b"xyz", private_key=b"zyx")


def test_waescrow_escrow_api_workflow(db):

    escrow_proxy = TestingServiceProxy(
        client=Client(), service_url="/json/", version="2.0"
    )

    keychain_uid = uuid.uuid4()
    key_type= "RSA"
    secret = get_random_bytes(101)

    public_key_pem = _get_jsonrpc_result(escrow_proxy.get_public_key(keychain_uid=keychain_uid, key_type="RSA"))
    public_key = load_asymmetric_key_from_pem_bytestring(
        key_pem=public_key_pem, key_type=key_type
    )

    signature = _get_jsonrpc_result(escrow_proxy.get_message_signature(
            keychain_uid=keychain_uid, message=secret, key_type=key_type, signature_algo="PSS"
    ))
    verify_message_signature(
        message=secret, signature=signature, key=public_key, signature_algo="PSS"
    )

    signature["digest"] += b"xyz"
    with pytest.raises(ValueError, match="Incorrect signature"):
        verify_message_signature(
            message=secret, signature=signature, key=public_key, signature_algo="PSS"
        )

    cipherdict = _encrypt_via_rsa_oaep(plaintext=secret, key=public_key)

    def _attempt_decryption():
        return escrow_proxy.decrypt_with_private_key(
                    keychain_uid=keychain_uid, key_type=key_type, encryption_algo="RSA_OAEP", cipherdict=cipherdict
            )

    with freeze_time() as frozen_datetime:

        with pytest.raises(RuntimeError, match="Decryption not authorized"):
            _attempt_decryption()

        keypair_obj = EscrowKeypair.objects.get(keychain_uid=keychain_uid, key_type=key_type)
        keypair_obj.decryption_authorized_at = timezone.now() + timedelta(hours = 2)
        keypair_obj.save()

        with pytest.raises(RuntimeError, match="Decryption authorization is not currently active"):
            _attempt_decryption()  # Too early

        frozen_datetime.tick(delta=timedelta(hours=3))

        decrypted = _get_jsonrpc_result(_attempt_decryption())
        assert decrypted == secret  # It works!

        cipherdict["digest_list"].append(b"aaabbbccc")
        with pytest.raises(ValueError, match="Ciphertext with incorrect length"):
            # Django test client reraises signalled exception
            escrow_proxy.decrypt_with_private_key(
                    keychain_uid=keychain_uid, key_type=key_type, encryption_algo="RSA_OAEP", cipherdict=cipherdict
            )

        frozen_datetime.tick(delta=timedelta(hours=24))  # We hardcode DECRYPTION_AUTHORIZATION_LIFESPAN_H here

        with pytest.raises(RuntimeError, match="Decryption authorization is not currently active"):
            _attempt_decryption()  # Too late, cipherdict is not even used so no ValueError

        keypair_obj.decryption_authorized_at = None
        keypair_obj.save()

        with pytest.raises(RuntimeError, match="Decryption not authorized"):
            _attempt_decryption()  # No more authorization at all


def test_waescrow_wsgi_application(db):
    from waescrow.wsgi import application
    with pytest.raises(KeyError, match="REQUEST_METHOD"):
        application(environ={}, start_response=lambda *args, **kwargs: None)
