from datetime import timedelta

import pytest
from Crypto.Random import get_random_bytes
from django.core.management import call_command
from django.db import IntegrityError
from django.utils import timezone
from freezegun import freeze_time
from io import StringIO

from wacryptolib.cipher import _encrypt_via_rsa_oaep
from wacryptolib.cryptainer import (
    encrypt_payload_into_cryptainer,
    decrypt_payload_from_cryptainer,
    gather_trustee_dependencies,
    request_decryption_authorizations,
    CRYPTAINER_TRUSTEE_TYPES,
)
from wacryptolib.exceptions import (
    KeyDoesNotExist,
    SignatureVerificationError,
    AuthorizationError,
    ValidationError,
    DecryptionError,
)
from wacryptolib.jsonrpc_client import JsonRpcProxy, status_slugs_response_error_handler
from wacryptolib.keygen import load_asymmetric_key_from_pem_bytestring
from wacryptolib.keystore import InMemoryKeystore
from wacryptolib.keystore import generate_free_keypair_for_least_provisioned_key_algo
from wacryptolib.scaffolding import (
    check_keystore_basic_get_set_api,
    check_keystore_free_keys_api,
    check_keystore_free_keys_concurrency,
)
from wacryptolib.signature import verify_message_signature
from wacryptolib.utilities import generate_uuid0
from waserver.apps.watrustee.core import SqlKeystore, _fetch_key_object_or_raise
from waserver.apps.watrustee.models import TrusteeKeypair


def _get_trustee_jsonrpc_url(live_server):
    return live_server.url + "/trustee/jsonrpc/"


def test_sql_keystore_basic_and_free_keys_api(db):
    sql_keystore = SqlKeystore()

    test_locals = check_keystore_basic_get_set_api(sql_keystore)
    keychain_uid = test_locals["keychain_uid"]
    key_algo = test_locals["key_algo"]

    check_keystore_free_keys_api(sql_keystore)

    representation = repr(TrusteeKeypair.objects.first())
    assert "ui" in representation

    with pytest.raises(IntegrityError):  # Final tests, since it breaks current DB transaction
        TrusteeKeypair.objects.create(
            keychain_uid=keychain_uid, key_algo=key_algo, public_key=b"hhhh", private_key=b"jjj"
        )


@pytest.mark.django_db(transaction=True)
def test_sql_keystore_free_keys_concurrent_transactions():
    """This test runs outside SQL transactions, and checks the handling of concurrency via threading locks."""
    sql_keystore = SqlKeystore()
    check_keystore_free_keys_concurrency(sql_keystore)


def test_jsonrpc_trustee_signature(live_server):
    jsonrpc_url = _get_trustee_jsonrpc_url(live_server)

    trustee_proxy = JsonRpcProxy(url=jsonrpc_url, response_error_handler=status_slugs_response_error_handler)

    keychain_uid = generate_uuid0()
    payload_signature_algo = "DSA_DSS"
    secret = get_random_bytes(101)
    secret_too_big = get_random_bytes(150)

    with pytest.raises(ValidationError):
        trustee_proxy.fetch_public_key()

    public_key_signature_pem = trustee_proxy.fetch_public_key(
        keychain_uid=keychain_uid, key_algo=payload_signature_algo
    )
    public_key_signature = load_asymmetric_key_from_pem_bytestring(
        key_pem=public_key_signature_pem, key_algo=payload_signature_algo
    )

    with pytest.raises(ValidationError):
        trustee_proxy.get_message_signature()

    signature = trustee_proxy.get_message_signature(
        keychain_uid=keychain_uid, message=secret, signature_algo=payload_signature_algo
    )

    with pytest.raises(ValidationError, match="too big"):
        trustee_proxy.get_message_signature(
            keychain_uid=keychain_uid, message=secret_too_big, signature_algo=payload_signature_algo
        )

    verify_message_signature(
        message=secret, signature=signature, key=public_key_signature, signature_algo=payload_signature_algo
    )

    signature["signature_value"] += b"xyz"
    with pytest.raises(SignatureVerificationError, match="not authentic|Incorrect signature"):
        verify_message_signature(
            message=secret, signature=signature, key=public_key_signature, signature_algo=payload_signature_algo
        )


def test_jsonrpc_trustee_decryption_authorization_flags(live_server):
    jsonrpc_url = _get_trustee_jsonrpc_url(live_server)

    trustee_proxy = JsonRpcProxy(url=jsonrpc_url, response_error_handler=status_slugs_response_error_handler)

    keychain_uid = generate_uuid0()
    keychain_uid_bad = generate_uuid0()
    key_cipher_algo = "RSA_OAEP"
    secret = get_random_bytes(101)

    public_encryption_key_pem = trustee_proxy.fetch_public_key(keychain_uid=keychain_uid, key_algo=key_cipher_algo)
    public_encryption_key = load_asymmetric_key_from_pem_bytestring(
        key_pem=public_encryption_key_pem, key_algo=key_cipher_algo
    )

    cipherdict = _encrypt_via_rsa_oaep(plaintext=secret, key_dict=dict(key=public_encryption_key))

    def _attempt_decryption():
        return trustee_proxy.decrypt_with_private_key(
            keychain_uid=keychain_uid, cipher_algo=key_cipher_algo, cipherdict=cipherdict
        )

    with freeze_time() as frozen_datetime:
        with pytest.raises(AuthorizationError, match="Decryption not authorized"):
            _attempt_decryption()

        keypair_obj = TrusteeKeypair.objects.get(keychain_uid=keychain_uid, key_algo=key_cipher_algo)
        keypair_obj.decryption_authorized_at = timezone.now() + timedelta(hours=2)
        keypair_obj.save()

        with pytest.raises(AuthorizationError, match="Decryption authorization is only valid from"):
            _attempt_decryption()  # Too early

        frozen_datetime.tick(delta=timedelta(hours=3))

        with pytest.raises(ValidationError):
            trustee_proxy.decrypt_with_private_key()

        decrypted = _attempt_decryption()
        assert decrypted == secret  # It works!

        with pytest.raises(KeyDoesNotExist, match="not found"):
            trustee_proxy.decrypt_with_private_key(
                keychain_uid=keychain_uid_bad, cipher_algo=key_cipher_algo, cipherdict=cipherdict
            )

        cipherdict["ciphertext_chunks"].append(b"aaabbbccc")
        with pytest.raises(DecryptionError, match="Ciphertext with incorrect length"):
            trustee_proxy.decrypt_with_private_key(
                keychain_uid=keychain_uid, cipher_algo=key_cipher_algo, cipherdict=cipherdict
            )

        frozen_datetime.tick(delta=timedelta(hours=24))  # We hardcode DECRYPTION_AUTHORIZATION_LIFESPAN_H here

        with pytest.raises(AuthorizationError, match="Decryption authorization is only valid from"):
            _attempt_decryption()  # Too late, cipherdict is not even used so no ValueError

        keypair_obj.decryption_authorized_at = None
        keypair_obj.save()

        with pytest.raises(AuthorizationError, match="Decryption not authorized"):
            _attempt_decryption()  # No more authorization at all


def test_jsonrpc_trustee_request_decryption_authorization_for_normal_keys(live_server):
    jsonrpc_url = _get_trustee_jsonrpc_url(live_server)

    trustee_proxy = JsonRpcProxy(url=jsonrpc_url, response_error_handler=status_slugs_response_error_handler)

    key_cipher_algo = "RSA_OAEP"

    with freeze_time() as frozen_datetime:  # TEST AUTHORIZATION REQUEST HANDLING

        keychain_uid1 = generate_uuid0()
        keychain_uid2 = generate_uuid0()
        keychain_uid3 = generate_uuid0()
        keychain_uid4 = generate_uuid0()
        keychain_uid_unexisting = generate_uuid0()

        all_keypair_identifiers = [
            dict(keychain_uid=keychain_uid1, key_algo=key_cipher_algo),
            dict(keychain_uid=keychain_uid2, key_algo=key_cipher_algo),
            dict(keychain_uid=keychain_uid3, key_algo=key_cipher_algo),
            dict(keychain_uid=keychain_uid4, key_algo=key_cipher_algo),
            dict(keychain_uid=keychain_uid_unexisting, key_algo=key_cipher_algo),
        ]

        public_key_pem = trustee_proxy.fetch_public_key(keychain_uid=keychain_uid1, key_algo=key_cipher_algo)
        assert public_key_pem
        assert not _fetch_key_object_or_raise(
            keychain_uid=keychain_uid1, key_algo=key_cipher_algo
        ).decryption_authorized_at

        # Non-pregenerated keys don't have that field set!
        assert not _fetch_key_object_or_raise(keychain_uid=keychain_uid1, key_algo=key_cipher_algo).attached_at

        result = trustee_proxy.request_decryption_authorization(
            keypair_identifiers=[], request_message="I want decryption!"
        )
        assert result["success_count"] == 0
        assert result["too_old_count"] == 0
        assert result["not_found_count"] == 0

        frozen_datetime.tick(delta=timedelta(minutes=2))

        with pytest.raises(ValidationError):
            trustee_proxy.request_decryption_authorization()

        result = trustee_proxy.request_decryption_authorization(
            keypair_identifiers=all_keypair_identifiers, request_message="I want decryption!"
        )
        assert result["success_count"] == 1
        assert result["too_old_count"] == 0
        assert result["not_found_count"] == 4  # keychain_uid2 and keychain_uid3 not created yet

        old_decryption_authorized_at = _fetch_key_object_or_raise(
            keychain_uid=keychain_uid1, key_algo=key_cipher_algo
        ).decryption_authorized_at
        assert old_decryption_authorized_at

        public_key_pem = trustee_proxy.fetch_public_key(keychain_uid=keychain_uid2, key_algo=key_cipher_algo)
        assert public_key_pem
        public_key_pem = trustee_proxy.fetch_public_key(keychain_uid=keychain_uid3, key_algo=key_cipher_algo)
        assert public_key_pem

        frozen_datetime.tick(delta=timedelta(minutes=4))

        result = trustee_proxy.request_decryption_authorization(
            keypair_identifiers=all_keypair_identifiers, request_message="I want decryption!"
        )
        assert result["success_count"] == 2
        assert result["too_old_count"] == 1
        assert result["not_found_count"] == 2

        assert (
            _fetch_key_object_or_raise(keychain_uid=keychain_uid1, key_algo=key_cipher_algo).decryption_authorized_at
            == old_decryption_authorized_at
        )  # Unchanged
        assert _fetch_key_object_or_raise(keychain_uid=keychain_uid2, key_algo=key_cipher_algo).decryption_authorized_at
        assert _fetch_key_object_or_raise(keychain_uid=keychain_uid3, key_algo=key_cipher_algo).decryption_authorized_at

        with pytest.raises(KeyDoesNotExist, match="not found"):
            _fetch_key_object_or_raise(keychain_uid=keychain_uid_unexisting, key_algo=key_cipher_algo)

        public_key_pem = trustee_proxy.fetch_public_key(keychain_uid=keychain_uid4, key_algo=key_cipher_algo)
        assert public_key_pem

        frozen_datetime.tick(delta=timedelta(minutes=6))

        result = trustee_proxy.request_decryption_authorization(
            keypair_identifiers=all_keypair_identifiers, request_message="I want decryption!"
        )
        assert result["success_count"] == 0
        assert result["too_old_count"] == 4
        assert result["not_found_count"] == 1

        assert (
            _fetch_key_object_or_raise(keychain_uid=keychain_uid1, key_algo=key_cipher_algo).decryption_authorized_at
            == old_decryption_authorized_at
        )  # Unchanged

    del all_keypair_identifiers


def test_jsonrpc_trustee_request_decryption_authorization_for_free_keys(live_server):
    jsonrpc_url = _get_trustee_jsonrpc_url(live_server)

    trustee_proxy = JsonRpcProxy(url=jsonrpc_url, response_error_handler=status_slugs_response_error_handler)

    keychain_uid_free = generate_uuid0()
    free_key_algo1 = "RSA_OAEP"
    free_key_algo2 = "ECC_DSS"
    free_key_algo3 = "DSA_DSS"

    all_requested_keypair_identifiers = [
        dict(keychain_uid=keychain_uid_free, key_algo=free_key_algo1),
        dict(keychain_uid=keychain_uid_free, key_algo=free_key_algo2),
    ]

    sql_keystore = SqlKeystore()

    with freeze_time() as frozen_datetime:  # TEST RELATION WITH FREE KEYS ATTACHMENT

        for i in range(3):  # Generate 1 free keypair per type
            has_generated = generate_free_keypair_for_least_provisioned_key_algo(
                keystore=sql_keystore,
                max_free_keys_per_algo=1,
                key_algos=[free_key_algo1, free_key_algo2, free_key_algo3],
            )
            assert has_generated

        keys_generated_before_datetime = timezone.now()

        public_key_pem1 = trustee_proxy.fetch_public_key(keychain_uid=keychain_uid_free, key_algo=free_key_algo1)
        assert public_key_pem1

        # This key will not have early-enough request for authorization
        public_key_pem3 = trustee_proxy.fetch_public_key(keychain_uid=keychain_uid_free, key_algo=free_key_algo3)
        assert public_key_pem3

        with pytest.raises(ValidationError):
            trustee_proxy.request_decryption_authorization()

        result = trustee_proxy.request_decryption_authorization(
            keypair_identifiers=all_requested_keypair_identifiers, request_message="I want early decryption!"
        )
        assert result["success_count"] == 1
        assert result["too_old_count"] == 0
        assert result["not_found_count"] == 1  # free_key_algo2 is not attached yet

        frozen_datetime.tick(delta=timedelta(minutes=6))

        public_key_pem2 = trustee_proxy.fetch_public_key(keychain_uid=keychain_uid_free, key_algo=free_key_algo2)
        assert public_key_pem2

        result = trustee_proxy.request_decryption_authorization(
            keypair_identifiers=all_requested_keypair_identifiers, request_message="I want later decryption!"
        )
        assert result["success_count"] == 1  # It's attachment time which counts!
        assert result["too_old_count"] == 1  # First key is too old now
        assert result["not_found_count"] == 0

        keypair_obj = TrusteeKeypair.objects.get(keychain_uid=keychain_uid_free, key_algo=free_key_algo1)
        assert keypair_obj.created_at <= keys_generated_before_datetime
        assert keypair_obj.attached_at
        assert keypair_obj.decryption_authorized_at
        first_authorized_at = keypair_obj.decryption_authorized_at

        keypair_obj = TrusteeKeypair.objects.get(keychain_uid=keychain_uid_free, key_algo=free_key_algo2)
        assert keypair_obj.created_at <= keys_generated_before_datetime
        assert keypair_obj.attached_at
        assert keypair_obj.decryption_authorized_at
        assert keypair_obj.decryption_authorized_at >= first_authorized_at + timedelta(minutes=5)

        keypair_obj = TrusteeKeypair.objects.get(keychain_uid=keychain_uid_free, key_algo=free_key_algo3)
        assert keypair_obj.created_at <= keys_generated_before_datetime
        assert keypair_obj.attached_at
        assert not keypair_obj.decryption_authorized_at  # Never requested


def test_jsonrpc_trustee_encrypt_decrypt_cryptainer(live_server):
    jsonrpc_url = _get_trustee_jsonrpc_url(live_server)

    cryptoconf = dict(
        payload_cipher_layers=[
            # First we encrypt with local key and sign via main remote trustee
            dict(
                payload_cipher_algo="AES_EAX",
                key_cipher_layers=[
                    dict(
                        key_cipher_algo="RSA_OAEP",
                        key_cipher_trustee=dict(
                            trustee_type=CRYPTAINER_TRUSTEE_TYPES.JSONRPC_API_TRUSTEE, jsonrpc_url=jsonrpc_url
                        ),
                    )
                ],
                payload_signatures=[
                    dict(
                        payload_digest_algo="SHA512",
                        payload_signature_algo="DSA_DSS",
                        payload_signature_trustee=dict(
                            trustee_type=CRYPTAINER_TRUSTEE_TYPES.JSONRPC_API_TRUSTEE, jsonrpc_url=jsonrpc_url
                        ),
                    )
                ],
            )
        ]
    )

    # CASE 1: authorization request well sent a short time after creation of "keychain_uid" keypair, so decryption is accepted
    with freeze_time() as frozen_datetime:
        keychain_uid = generate_uuid0()
        payload = get_random_bytes(101)

        cryptainer = encrypt_payload_into_cryptainer(
            payload=payload,
            cryptoconf=cryptoconf,
            cryptainer_metadata=None,
            keychain_uid=keychain_uid,
            keystore_pool=None,  # Unused by this config actually
        )

        frozen_datetime.tick(delta=timedelta(minutes=3))

        with pytest.raises(AuthorizationError):
            decrypt_payload_from_cryptainer(cryptainer=cryptainer, keystore_pool=None)

        # Access automatically granted for now, with this trustee, when keys are young
        trustee_dependencies = gather_trustee_dependencies(cryptainers=[cryptainer])
        decryption_authorization_requests_result = request_decryption_authorizations(
            trustee_dependencies, keystore_pool=None, request_message="I need access to this"
        )
        print(">>>>> request_decryption_authorizations is", decryption_authorization_requests_result)

        decrypted_data = decrypt_payload_from_cryptainer(cryptainer=cryptainer, keystore_pool=None)
        assert decrypted_data == payload

        frozen_datetime.tick(delta=timedelta(hours=23))  # Once authorization is granted, it stays so for a long time
        decrypted_data = decrypt_payload_from_cryptainer(cryptainer=cryptainer, keystore_pool=None)
        assert decrypted_data == payload

        frozen_datetime.tick(
            delta=timedelta(hours=2)
        )  # Authorization has expired, and grace period to get one has long expired
        with pytest.raises(AuthorizationError, match="Decryption authorization is only valid from"):
            decrypt_payload_from_cryptainer(cryptainer=cryptainer, keystore_pool=None)

    # CASE 2: authorization request sent too late after creation of "keychain_uid" keypair, so decryption is rejected

    with freeze_time() as frozen_datetime:
        keychain_uid = generate_uuid0()
        data = get_random_bytes(101)
        local_keystore = InMemoryKeystore()

        cryptainer = encrypt_payload_into_cryptainer(
            payload=payload,
            cryptoconf=cryptoconf,
            cryptainer_metadata=None,
            keychain_uid=keychain_uid,
            keystore_pool=None,  # Unused by this config actually
        )

        frozen_datetime.tick(delta=timedelta(minutes=6))  # More than the 5 minutes grace period
        with pytest.raises(AuthorizationError, match="Decryption not authorized"):
            decrypt_payload_from_cryptainer(cryptainer=cryptainer, keystore_pool=None)


def test_management_command_generate_free_keys(db):

    sql_keystore = SqlKeystore()

    assert sql_keystore.get_free_keypairs_count("RSA_OAEP") == 0

    out_stream = StringIO()
    call_command("generate_free_keys", "1", stdout=out_stream)
    output = out_stream.getvalue()
    print(output)

    assert "Launching generate_free_keys.py script with max_free_keys_per_algo=1" in output
    assert "No more need for additional free keys" in output

    assert output.count("New iteration") == 5  # 1 key x 4 key types, and final iteration for nothing
    assert sql_keystore.get_free_keypairs_count("RSA_OAEP") == 1
