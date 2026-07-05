import io
import json
import unittest
from urllib.error import HTTPError

from ai_assist_auth_service.google_oauth_adapter import (
    GoogleOAuthExchangeError,
    GoogleOAuthHttpTokenExchange,
)


class StaticSecretResolver:
    def resolve(self, _secret_ref):
        return "client-secret"


class Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


class GoogleOAuthHttpTokenExchangeTest(unittest.TestCase):
    def test_exchange_code_maps_google_token_http_error_to_safe_error(self):
        def opener(request, timeout):
            self.assertEqual(timeout, 10)
            self.assertIn(b"client_secret=client-secret", request.data)
            raise HTTPError(
                request.full_url,
                401,
                "Unauthorized",
                {},
                io.BytesIO(json.dumps({"error": "invalid_client"}).encode("utf-8")),
            )

        exchange = GoogleOAuthHttpTokenExchange(
            client_id="client-id",
            client_secret_resolver=StaticSecretResolver(),
            client_secret_ref="secret-ref",
            opener=opener,
        )

        with self.assertRaises(GoogleOAuthExchangeError) as caught:
            exchange.exchange_code(
                authorization_code="authorization-code-secret",
                redirect_uri="https://api.example.com/oauth/google/callback",
            )

        self.assertEqual(caught.exception.error_code, "invalid_client")
        self.assertEqual(caught.exception.status, 401)
        self.assertEqual(caught.exception.step, "token")

    def test_exchange_code_maps_userinfo_http_error_to_safe_error(self):
        calls = []

        def opener(request, timeout):
            self.assertEqual(timeout, 10)
            calls.append(request.full_url)
            if request.full_url == "https://oauth2.googleapis.com/token":
                return Response(
                    {
                        "access_token": "access-token-secret",
                        "refresh_token": "refresh-token-secret",
                        "expires_in": 3600,
                        "scope": "https://www.googleapis.com/auth/documents",
                    }
                )
            raise HTTPError(
                request.full_url,
                403,
                "Forbidden",
                {},
                io.BytesIO(json.dumps({"error": "insufficient_scope"}).encode("utf-8")),
            )

        exchange = GoogleOAuthHttpTokenExchange(
            client_id="client-id",
            client_secret_resolver=StaticSecretResolver(),
            client_secret_ref="secret-ref",
            opener=opener,
        )

        with self.assertRaises(GoogleOAuthExchangeError) as caught:
            exchange.exchange_code(
                authorization_code="authorization-code-secret",
                redirect_uri="https://api.example.com/oauth/google/callback",
            )

        self.assertEqual(calls[-1], "https://openidconnect.googleapis.com/v1/userinfo")
        self.assertEqual(caught.exception.error_code, "insufficient_scope")
        self.assertEqual(caught.exception.status, 403)
        self.assertEqual(caught.exception.step, "userinfo")


if __name__ == "__main__":
    unittest.main()
