
# File: jwks_server.py
#---------------------------------------------------------
#%%
#!pip install flask 
#!pip install cryptography

#%%
from flask import Flask, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

import hashlib

#%%
app = Flask(__name__)

# Store the JWKS keys
jwks_keys = []

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_jwk(private_key):
    public_key = private_key.public_key()
    kid = hashlib.sha256(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )).hexdigest()

    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": public_key.public_numbers().n,
        "e": public_key.public_numbers().e,
        "exp": int((datetime.utcnow() + timedelta(days=365)).timestamp())
    }

@app.route('/jwks', methods=['GET'])
def get_jwks():
    return jsonify({"keys": jwks_keys})

if __name__ == '__main__':
    # Generate an initial key pair and add it to the JWKS
    private_key, _ = generate_rsa_key_pair()
    jwks_keys.append(generate_jwk(private_key))

    # Run the Flask app
    app.run(debug=True)
