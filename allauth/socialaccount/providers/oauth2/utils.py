import base64
import hashlib
import random
from secrets import token_urlsafe


def generate_code_challenge(code_challenge_method="S256"):
    # minimum length of 43 characters, maximum length of 128 characters
    nbytes = random.randint(43, 128)
    code_verifier = token_urlsafe(nbytes)
    if code_challenge_method == "plain":
        code_challenge = code_verifier
    else:
        hashed_verifier = hashlib.sha256(code_verifier.encode("ascii"))
        code_challenge = base64.urlsafe_b64encode(hashed_verifier.digest())
    return {
        "code_verifier": code_verifier,
        "code_challenge_method": code_challenge_method,
        "code_challenge": code_challenge
    }
