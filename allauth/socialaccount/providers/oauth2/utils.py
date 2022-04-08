import base64
import hashlib
import random
from secrets import token_urlsafe


def generate_code_challenge():
    # minimum length of 43 characters, maximum length of 128 characters
    nbytes = random.randint(43, 128)
    code_verifier = token_urlsafe(nbytes)
    hashed_verifier = hashlib.sha256(code_verifier.encode("ascii"))
    code_challenge = base64.urlsafe_b64encode(hashed_verifier.digest())
    return {
        "code_verifier": code_verifier,
        "code_challenge_method": "S256",
        "code_challenge": code_challenge,
    }
