import random
from datetime import timedelta

import pytest
from Crypto.Random import get_random_bytes
from bson.json_util import dumps, loads
from django.conf import settings
from django.db import IntegrityError
from django.test import Client
from django.utils import timezone
from freezegun import freeze_time

from wacryptolib.container import encrypt_data_into_container, decrypt_data_from_container
from wacryptolib.encryption import _encrypt_via_rsa_oaep
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.key_generation import load_asymmetric_key_from_pem_bytestring
from wacryptolib.key_storage import DummyKeyStorage
from wacryptolib.scaffolding import check_key_storage_basic_get_set_api, check_key_storage_free_keys_api, \
    check_key_storage_free_keys_concurrency
from wacryptolib.signature import verify_message_signature
from wacryptolib.utilities import generate_uuid0
from waescrow.escrow import SqlKeyStorage, _fetch_key_object_or_none
from waescrow.models import EscrowKeypair


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
def test_jsonrpc_escrow_api_workflow(live_server):

    jsonrpc_url = live_server.url + "/json/"  # FIXME change url!!

    escrow_proxy = JsonRpcProxy(url=jsonrpc_url, response_error_handler=status_slugs_response_error_handler)

    keychain_uid = generate_uuid0()
    keychain_uid_bad = generate_uuid0()
    key_encryption_algo = "RSA_OAEP"
    signature_algo = "DSA_DSS"
    secret = get_random_bytes(101)
    secret_too_big = get_random_bytes(150)

    public_key_encryption_pem = escrow_proxy.get_public_key(keychain_uid=keychain_uid, key_type=key_encryption_algo)
    public_key_encryption = load_asymmetric_key_from_pem_bytestring(
        key_pem=public_key_encryption_pem, key_type=key_encryption_algo
    )

    public_key_signature_pem = escrow_proxy.get_public_key(keychain_uid=keychain_uid, key_type=signature_algo)
    public_key_signature = load_asymmetric_key_from_pem_bytestring(
        key_pem=public_key_signature_pem, key_type=signature_algo
    )

    signature = escrow_proxy.get_message_signature(
            keychain_uid=keychain_uid, message=secret, signature_algo=signature_algo
    )

    with pytest.raises(ValueError, match="too big"):
        escrow_proxy.get_message_signature(
            keychain_uid=keychain_uid, message=secret_too_big, signature_algo=signature_algo
        )

    verify_message_signature(
        message=secret, signature=signature, key=public_key_signature, signature_algo=signature_algo
    )

    signature["digest"] += b"xyz"
    with pytest.raises(ValueError, match="not authentic|Incorrect signature"):
        verify_message_signature(
            message=secret, signature=signature, key=public_key_signature, signature_algo=signature_algo
        )

    cipherdict = _encrypt_via_rsa_oaep(plaintext=secret, key=public_key_encryption)

    def _attempt_decryption():
        return escrow_proxy.decrypt_with_private_key(
                    keychain_uid=keychain_uid, encryption_algo=key_encryption_algo, cipherdict=cipherdict
            )

    with freeze_time() as frozen_datetime:  # TEST AUTHORIZATION FLAG IN DB

        with pytest.raises(RuntimeError, match="Decryption not authorized"):
            _attempt_decryption()

        keypair_obj = EscrowKeypair.objects.get(keychain_uid=keychain_uid, key_type=key_encryption_algo)
        keypair_obj.decryption_authorized_at = timezone.now() + timedelta(hours = 2)
        keypair_obj.save()

        with pytest.raises(RuntimeError, match="Decryption authorization is only valid from"):
            _attempt_decryption()  # Too early

        frozen_datetime.tick(delta=timedelta(hours=3))

        decrypted = _attempt_decryption()
        assert decrypted == secret  # It works!

        with pytest.raises(ValueError, match="Unexisting sql keypair"):
            escrow_proxy.decrypt_with_private_key(
                    keychain_uid=keychain_uid_bad, encryption_algo=key_encryption_algo, cipherdict=cipherdict
            )

        cipherdict["digest_list"].append(b"aaabbbccc")
        with pytest.raises(ValueError, match="Ciphertext with incorrect length"):
            escrow_proxy.decrypt_with_private_key(
                    keychain_uid=keychain_uid, encryption_algo=key_encryption_algo, cipherdict=cipherdict
            )

        frozen_datetime.tick(delta=timedelta(hours=24))  # We hardcode DECRYPTION_AUTHORIZATION_LIFESPAN_H here

        with pytest.raises(RuntimeError, match="Decryption authorization is only valid from"):
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
            dict(keychain_uid=keychain_uid1, key_type=key_encryption_algo),
            dict(keychain_uid=keychain_uid2, key_type=key_encryption_algo),
            dict(keychain_uid=keychain_uid3, key_type=key_encryption_algo),
            dict(keychain_uid=keychain_uid4, key_type=key_encryption_algo),
            dict(keychain_uid=keychain_uid_unexisting, key_type=key_encryption_algo)]

        public_key_pem = escrow_proxy.get_public_key(keychain_uid=keychain_uid1, key_type=key_encryption_algo)
        assert public_key_pem
        assert not _fetch_key_object_or_none(keychain_uid=keychain_uid1, key_type=key_encryption_algo).decryption_authorized_at

        result = escrow_proxy.request_decryption_authorization(keypair_identifiers=[],
                                         request_message="I want decryption!")
        assert result["success_count"] == 0
        assert result["too_old_count"] == 0
        assert result["not_found_count"] == 0

        frozen_datetime.tick(delta=timedelta(minutes=2))

        result = escrow_proxy.request_decryption_authorization(keypair_identifiers=all_keypair_identifiers,
                                         request_message="I want decryption!")
        assert result["success_count"] == 1
        assert result["too_old_count"] == 0
        assert result["not_found_count"] == 4  # keychain_uid2 and keychain_uid3 not created yet

        old_decryption_authorized_at = _fetch_key_object_or_none(keychain_uid=keychain_uid1, key_type=key_encryption_algo).decryption_authorized_at
        assert old_decryption_authorized_at

        public_key_pem = escrow_proxy.get_public_key(keychain_uid=keychain_uid2, key_type=key_encryption_algo)
        assert public_key_pem
        public_key_pem = escrow_proxy.get_public_key(keychain_uid=keychain_uid3, key_type=key_encryption_algo)
        assert public_key_pem

        frozen_datetime.tick(delta=timedelta(minutes=4))

        result = escrow_proxy.request_decryption_authorization(keypair_identifiers=all_keypair_identifiers,
                                         request_message="I want decryption!")
        assert result["success_count"] == 2
        assert result["too_old_count"] == 1
        assert result["not_found_count"] == 2

        assert _fetch_key_object_or_none(keychain_uid=keychain_uid1, key_type=key_encryption_algo).decryption_authorized_at == old_decryption_authorized_at  # Unchanged
        assert _fetch_key_object_or_none(keychain_uid=keychain_uid2, key_type=key_encryption_algo).decryption_authorized_at
        assert _fetch_key_object_or_none(keychain_uid=keychain_uid3, key_type=key_encryption_algo).decryption_authorized_at

        assert not _fetch_key_object_or_none(keychain_uid=keychain_uid_unexisting, key_type=key_encryption_algo)  # Unexisting still!

        public_key_pem = escrow_proxy.get_public_key(keychain_uid=keychain_uid4, key_type=key_encryption_algo)
        assert public_key_pem

        frozen_datetime.tick(delta=timedelta(minutes=6))

        result = escrow_proxy.request_decryption_authorization(keypair_identifiers=all_keypair_identifiers,
                                         request_message="I want decryption!")
        assert result["success_count"] == 0
        assert result["too_old_count"] == 4
        assert result["not_found_count"] == 1

        assert _fetch_key_object_or_none(keychain_uid=keychain_uid1, key_type=key_encryption_algo).decryption_authorized_at == old_decryption_authorized_at  # Unchanged


def test_jsonrpc_escrow_api_encrypt_decrypt_container(live_server):

    jsonrpc_url = live_server.url + "/json/"  # FIXME change url!!

    encryption_conf = dict(
        data_encryption_strata=[
            # First we encrypt with local key and sign via main remote escrow
            dict(
                data_encryption_algo="AES_EAX",
                key_encryption_strata=[
                    dict(
                        key_encryption_algo="RSA_OAEP",
                        key_escrow=dict(url=jsonrpc_url),
                    )
                ],
                data_signatures=[
                    dict(
                        message_prehash_algo="SHA512",
                        signature_algo="DSA_DSS",
                        signature_escrow=dict(url=jsonrpc_url),
                    )
                ],
            )])


    # CASE 1: authorization request well sent a short time after creation of "keychain_uid" keypair, so decryption is accepted

    with freeze_time() as frozen_datetime:

        keychain_uid = generate_uuid0()
        data = get_random_bytes(101)
        local_key_storage = DummyKeyStorage()

        container = encrypt_data_into_container(
            data=data,
            conf=encryption_conf,
            metadata=None,
            keychain_uid=keychain_uid,
            local_key_storage=local_key_storage  # Unused by this config actually
        )

        frozen_datetime.tick(delta=timedelta(minutes=3))
        # This call requests an authorization along the way
        decrypted_data = decrypt_data_from_container(container=container, local_key_storage=local_key_storage)
        assert decrypted_data == data

        frozen_datetime.tick(delta=timedelta(hours=23))  # Once authorization is granted, it stays so for al ong time
        decrypted_data = decrypt_data_from_container(container=container, local_key_storage=local_key_storage)
        assert decrypted_data == data

        frozen_datetime.tick(delta=timedelta(hours=2))  # Authorization has expired, and grace period to get one has long expired
        with pytest.raises(RuntimeError, match="Decryption authorization is only valid from"):
            decrypt_data_from_container(container=container, local_key_storage=local_key_storage)

    # CASE 2: authorization request sent too late after creation of "keychain_uid" keypair, so decryption is rejected

    with freeze_time() as frozen_datetime:

        keychain_uid = generate_uuid0()
        data = get_random_bytes(101)
        local_key_storage = DummyKeyStorage()

        container = encrypt_data_into_container(
            data=data,
            conf=encryption_conf,
            metadata=None,
            keychain_uid=keychain_uid,
            local_key_storage=local_key_storage  # Unused by this config actually
        )

        frozen_datetime.tick(delta=timedelta(minutes=6))  # More than the 5 minutes grace period
        with pytest.raises(RuntimeError, match="Decryption not authorized"):
            decrypt_data_from_container(container=container, local_key_storage=local_key_storage)


def test_crashdump_reports(db):
    client = Client(enforce_csrf_checks=True)

    crashdump = "sòme dâta %s" % random.randint(1, 10000)

    res = client.post("/crashdumps/")
    assert res.status_code == 400
    assert res.content == b"Missing crashdump field"

    res = client.post("/crashdumps/", data=dict(crashdump=crashdump))
    assert res.status_code == 200
    assert res.content == b"OK"

    dump_files = sorted(settings.CRASHDUMPS_DIR.iterdir())
    assert dump_files
    dump_file_content = dump_files[-1].read_text(encoding="utf8")
    assert dump_file_content == crashdump


def test_waescrow_wsgi_application(db):
    from waescrow.wsgi import application
    with pytest.raises(KeyError, match="REQUEST_METHOD"):
        application(environ={}, start_response=lambda *args, **kwargs: None)
