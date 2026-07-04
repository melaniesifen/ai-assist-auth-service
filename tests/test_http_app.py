from __future__ import annotations

import json
import unittest

from auth_test_helpers import create_auth_fixture, product_session
from ai_assist_auth_service import (  # noqa: E402
    AuthRuntimeConfig,
    GoogleOAuthFlowService,
    HmacProductSessionCodec,
    InMemoryOAuthStateRepository,
    SignedOAuthStateCodec,
)
from ai_assist_auth_service.http_app import AuthHttpApplication


class AuthHttpApplicationTest(unittest.TestCase):
    def test_login_session_status_and_logout_use_server_signed_product_session(self) -> None:
        app = self.create_app()

        login = app.handle(
            method="POST",
            path="/auth/login",
            body=json.dumps({"bootstrapSecret": "bootstrap-secret"}).encode("utf-8"),
        )
        login_body = self.decode(login)
        token = login_body["accessToken"]

        session = app.handle(
            method="GET",
            path="/auth/session",
            headers={"Authorization": f"Bearer {token}", "X-Request-Id": "req-2"},
        )
        session_body = self.decode(session)
        self.assertEqual(session_body["productSession"]["tenantId"], "tenant-1")
        self.assertEqual(session_body["productSession"]["userId"], "user-1")
        self.assertEqual(session_body["productSession"]["status"], "authenticated")
        self.assert_metadata_only(session_body)

        logout = app.handle(method="POST", path="/auth/logout", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(logout["status"], 200)
        rejected = app.handle(method="GET", path="/auth/session", headers={"Authorization": f"Bearer {token}"})
        rejected_body = self.decode(rejected)
        self.assertEqual(rejected_body["productSession"]["status"], "anonymous")
        self.assertEqual(rejected_body["productSession"]["error"]["code"], "AUTHENTICATION_REQUIRED")

    def test_oauth_start_callback_status_and_disconnect_use_canonical_routes(self) -> None:
        app = self.create_app()
        issued = app.product_session_codec.issue(
            tenant_id="tenant-1",
            user_id="user-1",
            auth_subject="auth0|subject-1",
        )
        headers = {"Authorization": f"Bearer {issued['token']}"}

        started_response = app.handle(
            method="POST",
            path="/oauth/google/start",
            headers=headers,
            body=json.dumps({"redirectTarget": "https://app.example.com"}).encode("utf-8"),
        )
        started = self.decode(started_response)
        self.assertIn("https://accounts.google.com/o/oauth2/v2/auth", started["authorizationUrl"])
        self.assert_metadata_only(started)

        callback = app.handle(
            method="GET",
            path="/oauth/google/callback",
            query={"state": [started["state"]], "code": ["authorization-code-secret"]},
        )
        self.assertEqual(callback["status"], 302)
        self.assertEqual(callback["headers"]["Location"], "https://app.example.com?googleOAuth=connected")

        status = self.decode(app.handle(method="GET", path="/oauth/google/status", headers=headers))
        self.assertTrue(status["connected"])
        self.assertEqual(status["accounts"][0]["googleAccountId"], "google-account-1")
        self.assert_metadata_only(status)

        disconnected = self.decode(
            app.handle(
                method="DELETE",
                path="/oauth/google/connection",
                headers=headers,
                query={"googleAccountId": ["google-account-1"]},
            )
        )
        self.assertEqual(disconnected["status"], "revoked")
        self.assert_metadata_only(disconnected)

    def test_oauth_callback_rejects_replayed_state(self) -> None:
        app = self.create_app()
        issued = app.product_session_codec.issue(
            tenant_id="tenant-1",
            user_id="user-1",
            auth_subject="auth0|subject-1",
        )
        headers = {"Authorization": f"Bearer {issued['token']}"}
        started = self.decode(
            app.handle(
                method="POST",
                path="/oauth/google/start",
                headers=headers,
                body=json.dumps({"redirectTarget": "https://app.example.com"}).encode("utf-8"),
            )
        )
        app.handle(
            method="GET",
            path="/oauth/google/callback",
            query={"state": [started["state"]], "code": ["authorization-code-secret"]},
        )

        replay = app.handle(
            method="GET",
            path="/oauth/google/callback",
            query={"state": [started["state"]], "code": ["authorization-code-secret"]},
        )

        self.assertEqual(replay["status"], 400)
        self.assert_metadata_only(self.decode(replay))

    def test_malformed_requests_return_safe_error_envelopes(self) -> None:
        app = self.create_app()

        malformed_body = app.handle(method="POST", path="/auth/login", body=b"{not-json")
        missing_callback_state = app.handle(
            method="GET",
            path="/oauth/google/callback",
            query={"code": ["authorization-code-secret"]},
        )

        self.assertEqual(malformed_body["status"], 400)
        self.assertEqual(self.decode(malformed_body)["error"]["code"], "VALIDATION_FAILED")
        self.assertEqual(missing_callback_state["status"], 400)
        self.assertEqual(self.decode(missing_callback_state)["error"]["code"], "VALIDATION_FAILED")
        self.assert_metadata_only(self.decode(malformed_body))
        self.assert_metadata_only(self.decode(missing_callback_state))

    def create_app(self) -> AuthHttpApplication:
        fixture = create_auth_fixture()
        runtime = AuthRuntimeConfig.from_mapping(
            {
                "APP_ENV": "dev",
                "AWS_REGION": "us-west-2",
                "TRUSTED_USER_MODE": "true",
                "ALLOWED_ORIGINS": "https://app.example.com",
                "WEB_APP_BASE_URL": "https://app.example.com",
                "API_BASE_URL": "https://api.example.com",
                "SSE_BASE_URL": "https://sse.example.com",
                "GOOGLE_OAUTH_CLIENT_ID": "client-1",
                "GOOGLE_OAUTH_CLIENT_SECRET_REF": "secret-ref",
                "GOOGLE_OAUTH_CALLBACK_URL": "https://api.example.com/oauth/google/callback",
                "APP_KMS_KEY_ID": "key-1",
                "OAUTH_TOKEN_TABLE_NAME": "OAuthTokens",
            }
        )
        flow = GoogleOAuthFlowService(
            oauth_token_service=fixture.oauth_token_service,
            state_repository=InMemoryOAuthStateRepository(),
            state_codec=SignedOAuthStateCodec(signing_secret="state-signing-secret"),
            token_exchange=fixture.token_exchange,
            client_id="client-1",
            redirect_uri="https://api.example.com/oauth/google/callback",
            allowed_redirect_targets=["https://app.example.com"],
            nonce_factory=lambda: "nonce-1",
        )
        return AuthHttpApplication(
            runtime_config=runtime,
            tenant_directory=fixture.tenant_directory,
            identity_service=fixture.identity_service,
            oauth_token_service=fixture.oauth_token_service,
            oauth_flow_service=flow,
            setup_status_service=fixture.setup_status_service,
            product_session_codec=HmacProductSessionCodec(
                signing_secret="product-session-secret",
                audience="ai-assist",
            ),
            trusted_user_tenant_id="tenant-1",
            trusted_user_user_id="user-1",
            trusted_user_auth_subject="auth0|subject-1",
            trusted_user_bootstrap_secret="bootstrap-secret",
        )

    def decode(self, response: dict[str, object]) -> dict[str, object]:
        return json.loads(response["body"].decode("utf-8"))

    def assert_metadata_only(self, payload: object) -> None:
        serialized = json.dumps(payload).lower()
        for disallowed in [
            "authorization-code-secret",
            "authorizationcode",
            "authorizationheader",
            "authorization:",
            "access-token-secret",
            "refresh-token-secret",
            "accesstoken",
            "refreshtoken",
            "ciphertext",
            "client_secret",
            "bearer ",
            "bootstrap-secret",
        ]:
            self.assertNotIn(disallowed, serialized)


if __name__ == "__main__":
    unittest.main()
