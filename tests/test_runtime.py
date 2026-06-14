from __future__ import annotations

import json
import unittest

from auth_test_helpers import (  # noqa: E402
    assert_auth_error,
    create_auth_fixture,
    product_session,
)
from ai_assist_auth_service import (  # noqa: E402
    AUTH_ERROR_CODES,
    AUTH_REFERENCE_TYPES,
    AuthRouteAuthorizer,
    AuthRuntimeConfig,
    GoogleOAuthFlowService,
    InMemoryOAuthStateRepository,
    SignedOAuthStateCodec,
)


class AuthRuntimeConfigTest(unittest.TestCase):
    def test_validates_deployed_runtime_config_and_exposes_metadata_only_flow_settings(self) -> None:
        config = AuthRuntimeConfig.from_mapping(runtime_env())

        self.assertEqual(config.expected_google_oauth_callback_url, "https://api.example.com/oauth/google/callback")
        self.assertEqual(
            config.google_oauth_flow_config(),
            {
                "clientId": "google-client-1",
                "redirectUri": "https://api.example.com/oauth/google/callback",
                "allowedRedirectTargets": ("https://app.example.com",),
            },
        )
        self.assertEqual(config.public_metadata()["sseBaseUrl"], "https://sse.example.com")
        self.assert_metadata_only(config.public_metadata())

    def test_direct_constructor_rejects_non_boolean_mode_and_non_sequence_origins(self) -> None:
        assert_auth_error(
            self,
            lambda: AuthRuntimeConfig(
                app_env="dev",
                aws_region="us-west-2",
                trusted_user_mode="sometimes",
                allowed_origins=["https://app.example.com"],
                web_app_base_url="https://app.example.com",
                api_base_url="https://api.example.com",
                sse_base_url="https://sse.example.com",
                google_oauth_client_id="google-client-1",
                google_oauth_callback_url="https://api.example.com/oauth/google/callback",
            ),
            AUTH_ERROR_CODES["VALIDATION_FAILED"],
            400,
        )
        assert_auth_error(
            self,
            lambda: AuthRuntimeConfig(
                app_env="dev",
                aws_region="us-west-2",
                trusted_user_mode=True,
                allowed_origins="https://app.example.com",
                web_app_base_url="https://app.example.com",
                api_base_url="https://api.example.com",
                sse_base_url="https://sse.example.com",
                google_oauth_client_id="google-client-1",
                google_oauth_callback_url="https://api.example.com/oauth/google/callback",
            ),
            AUTH_ERROR_CODES["VALIDATION_FAILED"],
            400,
        )

    def test_rejects_callback_url_mismatch_and_unsafe_nonlocal_http(self) -> None:
        assert_auth_error(
            self,
            lambda: AuthRuntimeConfig.from_mapping(
                runtime_env(GOOGLE_OAUTH_CALLBACK_URL="https://wrong.example.com/oauth/google/callback")
            ),
            AUTH_ERROR_CODES["VALIDATION_FAILED"],
            400,
        )
        assert_auth_error(
            self,
            lambda: AuthRuntimeConfig.from_mapping(runtime_env(API_BASE_URL="http://api.example.com")),
            AUTH_ERROR_CODES["VALIDATION_FAILED"],
            400,
        )

    def test_deployed_config_drives_oauth_callback_url_and_preserves_state_replay_protection(self) -> None:
        fixture = create_auth_fixture()
        config = AuthRuntimeConfig.from_mapping(runtime_env())
        flow_config = config.google_oauth_flow_config()
        flow = GoogleOAuthFlowService(
            oauth_token_service=fixture.oauth_token_service,
            state_repository=InMemoryOAuthStateRepository(),
            state_codec=SignedOAuthStateCodec(signing_secret="state-signing-secret"),
            token_exchange=fixture.token_exchange,
            client_id=flow_config["clientId"],
            redirect_uri=flow_config["redirectUri"],
            allowed_redirect_targets=flow_config["allowedRedirectTargets"],
            nonce_factory=lambda: "nonce-1",
        )
        identity = fixture.identity_service.derive_identity(product_session=product_session())

        start = flow.start_google_oauth(identity=identity, redirect_target="https://app.example.com")
        connected = flow.complete_google_oauth(
            identity=identity,
            state=start["state"],
            authorization_code="authorization-code-secret",
        )

        self.assertEqual(
            fixture.token_exchange.exchange_calls[0]["redirectUri"],
            "https://api.example.com/oauth/google/callback",
        )
        self.assertEqual(connected["status"], "connected")
        assert_auth_error(
            self,
            lambda: flow.complete_google_oauth(
                identity=identity,
                state=start["state"],
                authorization_code="authorization-code-secret",
            ),
            AUTH_ERROR_CODES["OAUTH_STATE_INVALID"],
            400,
        )
        self.assert_metadata_only(connected)

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
        ]:
            self.assertNotIn(disallowed, serialized)


class AuthRouteAuthorizerTest(unittest.TestCase):
    def test_authorizes_http_reference_with_server_derived_identity(self) -> None:
        fixture = create_auth_fixture()
        authorizer = AuthRouteAuthorizer(identity_service=fixture.identity_service)

        authorized = authorizer.authorize_http_request(
            product_session=product_session(),
            client_identity={"tenantId": "attacker-tenant", "userId": "attacker-user"},
            reference={
                "actionId": "action-1",
                "tenantId": "tenant-1",
                "userId": "user-1",
            },
            reference_type=AUTH_REFERENCE_TYPES["ACTION"],
        )

        self.assertEqual(authorized["transport"], "http")
        self.assertEqual(authorized["identity"]["tenantId"], "tenant-1")
        self.assertEqual(authorized["identity"]["userId"], "user-1")
        self.assertEqual(
            authorized["identity"]["ignoredClientIdentity"],
            {"tenantId": "attacker-tenant", "userId": "attacker-user"},
        )
        self.assertEqual(authorized["authorizedReference"]["referenceId"], "action-1")

    def test_authorizes_sse_stream_only_for_matching_session_reference(self) -> None:
        fixture = create_auth_fixture()
        authorizer = AuthRouteAuthorizer(identity_service=fixture.identity_service)

        authorized = authorizer.authorize_sse_stream(
            product_session=product_session(),
            session_reference={
                "sessionId": "session-1",
                "tenantId": "tenant-1",
                "userId": "user-1",
            },
        )

        self.assertEqual(authorized["transport"], "sse")
        self.assertEqual(authorized["authorizedReference"]["referenceType"], AUTH_REFERENCE_TYPES["SESSION"])
        assert_auth_error(
            self,
            lambda: authorizer.authorize_sse_stream(
                product_session=product_session(),
                session_reference={
                    "sessionId": "session-2",
                    "tenantId": "tenant-2",
                    "userId": "user-1",
                },
            ),
            AUTH_ERROR_CODES["TENANT_ACCESS_DENIED"],
            403,
        )
        assert_auth_error(
            self,
            lambda: authorizer.authorize_sse_stream(
                product_session=None,
                session_reference={
                    "sessionId": "session-1",
                    "tenantId": "tenant-1",
                    "userId": "user-1",
                },
            ),
            AUTH_ERROR_CODES["AUTHENTICATION_REQUIRED"],
            401,
        )


def runtime_env(**overrides: str) -> dict[str, str]:
    env = {
        "APP_ENV": "dev",
        "AWS_REGION": "us-west-2",
        "TRUSTED_USER_MODE": "true",
        "ALLOWED_ORIGINS": "https://app.example.com",
        "WEB_APP_BASE_URL": "https://app.example.com",
        "API_BASE_URL": "https://api.example.com",
        "SSE_BASE_URL": "https://sse.example.com",
        "GOOGLE_OAUTH_CLIENT_ID": "google-client-1",
        "GOOGLE_OAUTH_CALLBACK_URL": "https://api.example.com/oauth/google/callback",
    }
    env.update(overrides)
    return env


if __name__ == "__main__":
    unittest.main()
