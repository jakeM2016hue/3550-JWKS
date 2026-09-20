import time
import jwt
from flask import Flask, request, jsonify
from key import KeyStore

app = Flask(__name__)
key_store = KeyStore()  

@app.route("/.well-known/jwks.json", methods=["GET"]) #Return keys that are not expired
def get_jwks():
    return jsonify(key_store.get_jwks()), 200

@app.route("/auth", methods=["POST"]) #Generate a signed JWT token
def auth():
    use_expired = "expired" in request.args
    signing_key = key_store.get_signing_key(expired=use_expired)
    now = int(time.time())
    if use_expired: # Make the token expired by setting the issued_at and expires_at in the past
        issued_at = now - 7200
        expires_at = signing_key.expiry  
    else: # Make the token valid by setting the issued_at and expires_at in the future
        issued_at = now
        expires_at = now + 3600  
 
    payload = {
        "sub": "mock-user",
        "iat": issued_at,
        "exp": expires_at,
    }
 
    token = jwt.encode( # Sign the JWT with the private key and include the kid in the header
        payload,
        signing_key.private_key,
        algorithm="RS256",
        headers={"kid": signing_key.kid},
    )
 
    return jsonify({"token": token}), 200 # Return the signed JWT token in the response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080) 