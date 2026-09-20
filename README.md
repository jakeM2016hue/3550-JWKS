# 3550-JWKS
Project 1 3550 - Jake Moseley // jmm1103

# Files
* app.py — the Flask server and route handlers
* key.py — RSA key generation, expiry logic, and JWK formatting
* test_app.py — test suite (7 tests)

# Libraries used
* Flask — web server / routing
* PyJWT — signing and verifying JWTs
* cryptography — RSA key generation
* pytest / pytest-cov — testing and coverage

# Setup

* Requires Python 3.9+.
* python -m venv venv
venv\Scripts\activate        # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt

# Running the server
- python app.py

# The server runs on http://localhost:8080.

# Quick manual check (in a second terminal, while the server is running):

* curl http://localhost:8080/.well-known/jwks.json
* curl -X POST http://localhost:8080/auth
* curl -X POST "http://localhost:8080/auth?expired=true"

# Running the tests
* pytest --cov=. --cov-report=term-missing

# This runs 7 tests and prints the coverage percentage.
