import time
import unittest
import jwt

from app import app, key_store

class JWKSServerTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_jwks_returns_valid_key_only(self):
        """JWKS should be a 200 with a 'keys' list containing the valid
        key's kid, formatted as a proper RSA JWK."""
        response = self.client.get("/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        kids = [k["kid"] for k in data["keys"]]
        self.assertIn(key_store.valid_key.kid, kids)

        jwk = data["keys"][0]
        for field in ("kty", "use", "alg", "kid", "n", "e"):
            self.assertIn(field, jwk)
        self.assertEqual(jwk["kty"], "RSA")

    def test_jwks_excludes_expired_key(self):
        """The expired key's public material must never be published."""
        response = self.client.get("/.well-known/jwks.json")
        kids = [k["kid"] for k in response.get_json()["keys"]]
        self.assertNotIn(key_store.expired_key.kid, kids)

    def test_jwks_rejects_post(self):
        """Only GET should be allowed on the JWKS endpoint."""
        response = self.client.post("/.well-known/jwks.json")
        self.assertEqual(response.status_code, 405)

    def test_auth_returns_valid_signed_token(self):
        """POST /auth (no body) should return a token that verifies
        against the currently published (valid) public key and is not
        expired."""
        response = self.client.post("/auth")
        self.assertEqual(response.status_code, 200)

        token = response.get_json()["token"]
        header = jwt.get_unverified_header(token)
        self.assertEqual(header["kid"], key_store.valid_key.kid)

        decoded = jwt.decode(
            token, key_store.valid_key.public_key, algorithms=["RS256"]
        )
        self.assertEqual(decoded["sub"], "mock-user")
        self.assertGreater(decoded["exp"], int(time.time()))

    def test_auth_expired_returns_expired_token(self):
        """POST /auth?expired should return a token signed with the
        expired key, carrying a past exp, that fails normal
        verification."""
        response = self.client.post("/auth?expired=true")
        token = response.get_json()["token"]

        header = jwt.get_unverified_header(token)
        self.assertEqual(header["kid"], key_store.expired_key.kid)

        with self.assertRaises(jwt.ExpiredSignatureError):
            jwt.decode(
                token, key_store.expired_key.public_key, algorithms=["RS256"]
            )

    def test_auth_rejects_get(self):
        """Only POST should be allowed on the auth endpoint."""
        response = self.client.get("/auth")
        self.assertEqual(response.status_code, 405)

    def test_key_store_expiry_flags(self):
        """Sanity check on the underlying key expiry logic itself."""
        self.assertFalse(key_store.valid_key.is_expired())
        self.assertTrue(key_store.expired_key.is_expired())


if __name__ == "__main__":
    unittest.main()