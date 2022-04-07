import base64
import hashlib

from django.test.client import RequestFactory
from django.test.utils import override_settings
from django.urls import reverse

from allauth.account.utils import user_email
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
        },
        SOCIALACCOUNT_AUTO_SIGNUP=False
    )
    def test_login(self):
        resp_mocks = self.get_mocked_response()
        print("starting self.login\n")
        resp = self.login(resp_mocks)
        print("resp", resp.__dict__)
        # assert resp has a code_challn
        self.assertRedirects(resp, reverse("socialaccount_signup"))
        resp = self.client.get(reverse("socialaccount_signup"))
        sociallogin = resp.context["form"].sociallogin
        data = dict(
            email=user_email(sociallogin.user),
            username=str(58931054823194),
        )
        resp = self.client.post(reverse("socialaccount_signup"), data=data)
        self.assertRedirects(resp, "/accounts/profile/", fetch_redirect_response=False)
        user = resp.context["user"]
        self.assertFalse(user.has_usable_password())
