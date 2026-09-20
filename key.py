import base64
import time
import uuid
from typing import Optional
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import rsa
 
 
def _int_to_base64url(value: int) -> str: # Convert an integer to a base64url-encoded string without padding.
    byte_length = (value.bit_length() + 7) // 8
    value_bytes = value.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("ascii")
 
 
class Key:
    def __init__(self, expiry_offset_seconds: int):
        """Generate a new RSA key pair.

    Args:
        expiry_offset_seconds: seconds from now until this key
            expires. A negative value creates an already-expired key.
    """
        self.kid = str(uuid.uuid4())
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        self.expiry = int(time.time()) + expiry_offset_seconds
 
    def is_expired(self) -> bool:
        return time.time() >= self.expiry
 
    def to_jwk(self) -> dict: # Convert the public key to a JWK representation, including the necessary fields for JWKS.
        numbers = self.public_key.public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": _int_to_base64url(numbers.n),
            "e": _int_to_base64url(numbers.e),
        }
 
 
class KeyStore: # A simple in-memory key store that manages a valid and an expired RSA key pair, providing methods to retrieve signing keys and JWKS documents.
    """Holds the RSA keys used by the server: one currently valid key,
    and one already-expired key.
    """
    def __init__(self):
        # A key that is valid for the next hour.
        self.valid_key = Key(expiry_offset_seconds=3600)
        # A key that already expired an hour ago.
        self.expired_key = Key(expiry_offset_seconds=-3600)
 
    def get_signing_key(self, expired: bool = False) -> Key:
        return self.expired_key if expired else self.valid_key
 
    def get_jwks(self) -> dict:
        keys = [
            key.to_jwk()
            for key in (self.valid_key, self.expired_key)
            if not key.is_expired()
        ]
        return {"keys": keys}
 
    def find_key_by_kid(self, kid: str) -> "Key | None":
        for key in (self.valid_key, self.expired_key):
            if key.kid == kid:
                return key
        return None