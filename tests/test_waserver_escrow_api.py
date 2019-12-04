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
from wacryptolib.scaffolding import check_key_storage_basic_get_set_api, check_key_storage_free_keys_api, \
    check_key_storage_free_keys_concurrency
from wacryptolib.signature import verify_message_signature
from wacryptolib.utilities import generate_uuid0
from waescrow import escrow
from waescrow.escrow import SqlKeyStorage, _fetch_key_object_or_none
from waescrow.models import EscrowKeypair

assert proxy.loads
proxy.loads = loads
assert proxy.dumps
proxy.dumps = dumps


def _get_jsonrpc_result(response_dict):
    assert isinstance(response_dict, dict)
    assert "error" not in response_dict
    return response_dict["result"]


def test_sql_key_storage_basic_and_free_keys_api(db):  # FIXME factorize

    sql_key_storage = SqlKeyStorage()

    test_locals = check_key_storage_basic_get_set_api(sql_key_storage)
    keychain_uid = test_locals["keychain_uid"]
    key_type = test_locals["key_type"]

    check_key_storage_free_keys_api(sql_key_storage)

    representation = repr(EscrowKeypair.objects.first())
    assert "ui" in representation

    with pytest.raises(IntegrityError):  # Final tests, since it breaks current DB transaction
        EscrowKeypair.objects.create(keychain_uid=keychain_uid, key_type=key_type, public_key=b"hhhh", private_key=b"jjj")


@pytest.mark.django_db(transaction=True)
def test_sql_key_storage_free_keys_concurrent_transactions():
    """This test runs outside SQL transactions, and checks the handling of concurrency via threading locks."""
    sql_key_storage = SqlKeyStorage()
    check_key_storage_free_keys_concurrency(sql_key_storage)


# TODO factorize this test with part of wacryptolib testsuite
def test_waescrow_escrow_api_workflow(db):

    escrow_proxy = TestingServiceProxy(
        client=Client(), service_url="/json/", version="2.0"
    )

    keychain_uid = generate_uuid0()
    keychain_uid_bad = generate_uuid0()
    key_type= "RSA"
    secret = get_random_bytes(101)

    public_key_pem = _get_jsonrpc_result(escrow_proxy.get_public_key(keychain_uid=keychain_uid, key_type=key_type))
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

    with freeze_time() as frozen_datetime:  # TEST AUTHORIZATION FLAG IN DB

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

        with pytest.raises(ValueError, match="Unexisting"):
            # Django test client reraises signalled exception
            escrow_proxy.decrypt_with_private_key(
                    keychain_uid=keychain_uid_bad, key_type=key_type, encryption_algo="RSA_OAEP", cipherdict=cipherdict
            )

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

    with freeze_time() as frozen_datetime:  # TEST AUTHORIZATION REQUEST HANDLING

        keychain_uid1 = generate_uuid0()
        keychain_uid2 = generate_uuid0()
        keychain_uid3 = generate_uuid0()
        keychain_uid4 = generate_uuid0()
        keychain_uid_unexisting = generate_uuid0()

        all_keypair_identifiers = [
            dict(keychain_uid=keychain_uid1, key_type=key_type),
            dict(keychain_uid=keychain_uid2, key_type=key_type),
            dict(keychain_uid=keychain_uid3, key_type=key_type),
            dict(keychain_uid=keychain_uid4, key_type=key_type),
            dict(keychain_uid=keychain_uid_unexisting, key_type=key_type)]

        public_key_pem = _get_jsonrpc_result(escrow_proxy.get_public_key(keychain_uid=keychain_uid1, key_type=key_type))
        assert public_key_pem
        assert not _fetch_key_object_or_none(keychain_uid=keychain_uid1, key_type=key_type).decryption_authorized_at

        result = _get_jsonrpc_result(escrow_proxy.request_decryption_authorization(keypair_identifiers=[],
                                         request_message="I want decryption!"))
        assert result["success_count"] == 0
        assert result["too_old_count"] == 0
        assert result["not_found_count"] == 0

        frozen_datetime.tick(delta=timedelta(minutes=2))

        result = _get_jsonrpc_result(escrow_proxy.request_decryption_authorization(keypair_identifiers=all_keypair_identifiers,
                                         request_message="I want decryption!"))
        assert result["success_count"] == 1
        assert result["too_old_count"] == 0
        assert result["not_found_count"] == 4  # keychain_uid2 and keychain_uid3 not created yet

        old_decryption_authorized_at = _fetch_key_object_or_none(keychain_uid=keychain_uid1, key_type=key_type).decryption_authorized_at
        assert old_decryption_authorized_at

        public_key_pem = _get_jsonrpc_result(escrow_proxy.get_public_key(keychain_uid=keychain_uid2, key_type=key_type))
        assert public_key_pem
        public_key_pem = _get_jsonrpc_result(escrow_proxy.get_public_key(keychain_uid=keychain_uid3, key_type=key_type))
        assert public_key_pem

        frozen_datetime.tick(delta=timedelta(minutes=4))

        result = _get_jsonrpc_result(escrow_proxy.request_decryption_authorization(keypair_identifiers=all_keypair_identifiers,
                                         request_message="I want decryption!"))
        assert result["success_count"] == 2
        assert result["too_old_count"] == 1
        assert result["not_found_count"] == 2

        assert _fetch_key_object_or_none(keychain_uid=keychain_uid1, key_type=key_type).decryption_authorized_at == old_decryption_authorized_at  # Unchanged
        assert _fetch_key_object_or_none(keychain_uid=keychain_uid2, key_type=key_type).decryption_authorized_at
        assert _fetch_key_object_or_none(keychain_uid=keychain_uid3, key_type=key_type).decryption_authorized_at

        assert not _fetch_key_object_or_none(keychain_uid=keychain_uid_unexisting, key_type=key_type)  # Unexisting still!

        public_key_pem = _get_jsonrpc_result(escrow_proxy.get_public_key(keychain_uid=keychain_uid4, key_type=key_type))
        assert public_key_pem

        frozen_datetime.tick(delta=timedelta(minutes=6))

        result = _get_jsonrpc_result(escrow_proxy.request_decryption_authorization(keypair_identifiers=all_keypair_identifiers,
                                         request_message="I want decryption!"))
        assert result["success_count"] == 0
        assert result["too_old_count"] == 4
        assert result["not_found_count"] == 1

        assert _fetch_key_object_or_none(keychain_uid=keychain_uid1, key_type=key_type).decryption_authorized_at == old_decryption_authorized_at  # Unchanged


def test_waescrow_wsgi_application(db):
    from waescrow.wsgi import application
    with pytest.raises(KeyError, match="REQUEST_METHOD"):
        application(environ={}, start_response=lambda *args, **kwargs: None)
