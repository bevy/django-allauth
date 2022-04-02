import base64
import hashlib

from django.test.client import RequestFactory
from django.test.utils import override_settings

from allauth.socialaccount.tests import OAuth2TestsMixin
from allauth.tests import MockedResponse, TestCase

from .provider import OktaProvider


class OktaTests(OAuth2TestsMixin, TestCase):
    provider_id = OktaProvider.id

    def get_mocked_response(self):
        return MockedResponse(
            200,
            """
            {
                "sub": "00u33ow83pjQpCQJr1j8",
                "name": "Jon Smith",
                "locale": "AE",
                "email": "jsmith@example.com",
                "nickname": "Jon Smith",
                "preferred_username": "jsmith@example.com",
                "given_name": "Jon",
                "family_name": "Smith",
                "zoneinfo": "America/Los_Angeles",
                "updated_at": 1601285210,
                "email_verified": true
            }
        """,
        )

    @override_settings(
        SOCIALACCOUNT_PROVIDERS={
            "okta": {
                "OAUTH_PKCE_ENABLED": "True"
            },
        }
    )
    def test_provider_gets_pkce(self):
        provider = OktaProvider(RequestFactory().get("/login"))
        pkce_params = provider.get_pkce_params()
        print("pkce_params", pkce_params)
        assert 'code_challenge' in pkce_params
        assert 'code_verifier' in pkce_params
        hashed_verifier =  hashlib.sha256(pkce_params["code_verifier"].encode("ascii"))
        code_challenge = base64.urlsafe_b64encode(hashed_verifier.digest())
        assert pkce_params['code_challenge'] == code_challenge