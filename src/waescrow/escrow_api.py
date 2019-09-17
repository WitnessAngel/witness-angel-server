import uuid

from wacryptolib.encryption import _decrypt_via_rsa_oaep
from wacryptolib.escrow import KeyStorageBase, EscrowApi
from wacryptolib.key_generation import generate_asymmetric_keypair, load_asymmetric_key_from_pem_bytestring
from wacryptolib.signature import sign_message
from wacryptolib.utilities import load_from_json_str, dump_to_json_str
from waescrow.models import EscrowKeypair

_CACHED_KEYS = {}  # FIXME REPLACE BY REAL DB ASAP!!!!


class SqlKeyStorage(KeyStorageBase):

    # TODO - add layer of protection with own asymmetric key of Escrow!

    def get_keypair(self, keychain_uid: uuid.UUID, key_type: str) -> dict:
        try:
            keypair_obj = EscrowKeypair.objects.get(keychain_uid=keychain_uid, key_type=key_type)
            keypair_serialized = keypair_obj.keypair
            assert isinstance(keypair_serialized, str), repr(keypair_serialized)
            keypair = load_from_json_str(keypair_serialized)
            return keypair
        except EscrowKeypair.DoesNotExist:
            return None

    def set_keypair(self, keychain_uid: uuid.UUID, key_type: str, keypair: dict):
        keypair_serialized = dump_to_json_str(keypair)
        assert isinstance(keypair_serialized, str), repr(keypair_serialized)
        # Raises IntegrityError if this ID already exists
        EscrowKeypair.objects.create(keychain_uid=keychain_uid, key_type=key_type.upper(), keypair=keypair_serialized)


SQL_ESCROW_API = EscrowApi(storage=SqlKeyStorage())


'''

def _fetch_pem_keypair_with_caching(keychain_uid, key_type):  # FIXME - hack to turn into DB lookup
    existing_keypair = _CACHED_KEYS.get((keychain_uid, key_type))
    if existing_keypair:
        keypair = existing_keypair
    else:
        keypair = generate_asymmetric_keypair(key_type=key_type, serialize=True)
        _CACHED_KEYS[(keychain_uid, key_type)] = keypair
    return keypair


def get_public_key(keychain_uid: uuid.UUID, key_type: str) -> bytes:
    """
    Return a public key in PEM format bytestring, that caller shall use to encrypt its own symmetric keys,
    or to check a signature.
    """
    keypair_pem = _fetch_pem_keypair_with_caching(keychain_uid=keychain_uid, key_type=key_type)
    return keypair_pem["public_key"]


def get_message_signature(
        keychain_uid: uuid.UUID, message: bytes, key_type: str, signature_algo: str
) -> dict:
    """
    Return a signature structure corresponding to the provided key and signature types.
    """
    keypair_pem = _fetch_pem_keypair_with_caching(keychain_uid=keychain_uid, key_type=key_type)
    private_key = load_asymmetric_key_from_pem_bytestring(key_pem=keypair_pem["private_key"], key_type=key_type)

    signature = sign_message(
        message=message,
        signature_algo=signature_algo,
        key=private_key,
    )
    return signature


def decrypt_with_private_key(
        keychain_uid: uuid.UUID, key_type: str, encryption_algo: str, cipherdict: dict
) -> bytes:
    """
    Return the message (probably a symmetric key) decrypted with the corresponding key,
    as bytestring.
    """
    assert key_type.upper() == "RSA"  # Only supported key for now
    assert (
        encryption_algo.upper() == "RSA_OAEP"
    )  # Only supported asymmetric cipher for now

    keypair_pem = _fetch_pem_keypair_with_caching(keychain_uid=keychain_uid, key_type=key_type)
    private_key = load_asymmetric_key_from_pem_bytestring(key_pem=keypair_pem["private_key"], key_type=key_type)

    secret = _decrypt_via_rsa_oaep(cipherdict=cipherdict, key=private_key)
    return secret
'''
