from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

from auth_test_helpers import (  # noqa: E402
    BASE_TIME,
    LATER_TIME,
    assert_auth_error,
    create_auth_fixture,
    product_session,
)
from ai_assist_auth_service import (  # noqa: E402
    AUTH_ERROR_CODES,
    GOOGLE_OAUTH_SCOPES,
    GoogleOAuthFlowService,
    InMemoryOAuthStateRepository,
    SignedOAuthStateCodec,
)
from ai_assist_auth_service.google_oauth_adapter import GoogleOAuthExchangeError


class FakeAuditSink:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def emit(self, event: dict[str, object]) -> None:
        self.events.append(dict(event))


class GoogleOAuthFlowServiceTest(unittest.TestCase):
    def test_starts_google_oauth_with_signed_state_identity_binding_and_least_privilege_scopes(self) -> None:
        fixture = create_auth_fixture()
        audit_sink = FakeAuditSink()
        flow = self.create_flow(fixture=fixture, audit_sink=audit_sink)
        identity = fixture.identity_service.derive_identity(product_session=product_session())

        start = flow.start_google_oauth(identity=identity, redirect_target="/setup")

        self.assertEqual(start["provider"], "google")
        self.assertEqual(start["redirectTarget"], "/setup")
        self.assertEqual(start["scopes"], GOOGLE_OAUTH_SCOPES)
        parsed = urlparse(start["authorizationUrl"])
        query = parse_qs(parsed.query)
        self.assertEqual(query["client_id"], ["client-1"])
        self.assertEqual(query["redirect_uri"], ["https://app.example.com/oauth/google/callback"])
        self.assertEqual(query["response_type"], ["code"])
        self.assertEqual(query["scope"], [" ".join(GOOGLE_OAUTH_SCOPES)])
        self.assertEqual(query["access_type"], ["offline"])
        self.assertEqual(query["prompt"], ["consent"])
        self.assertEqual(query["state"], [start["state"]])
        state_payload = flow.state_codec.verify(start["state"])
        self.assertEqual(state_payload["tenantId"], "tenant-1")
        self.assertEqual(state_payload["userId"], "user-1")
        self.assertEqual(state_payload["redirectTarget"], "/setup")
        self.assertEqual(audit_sink.events[-1]["event"], "google_oauth_started")
        self.assert_metadata_only(start)
        self.assert_metadata_only(audit_sink.events)

    def test_rejects_unapproved_redirect_targets_before_state_creation(self) -> None:
        fixture = create_auth_fixture()
        flow = self.create_flow(fixture=fixture)
        identity = fixture.identity_service.derive_identity(product_session=product_session())

        assert_auth_error(
            self,
            lambda: flow.start_google_oauth(identity=identity, redirect_target="https://evil.example"),
            AUTH_ERROR_CODES["VALIDATION_FAILED"],
            400,
        )
        self.assertEqual(flow.state_repository.records, {})

    def test_callback_exchanges_code_stores_encrypted_tokens_and_returns_metadata_only_status(self) -> None:
        fixture = create_auth_fixture()
        audit_sink = FakeAuditSink()
        flow = self.create_flow(fixture=fixture, audit_sink=audit_sink)
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        start = flow.start_google_oauth(identity=identity, redirect_target="/setup")

        result = flow.complete_google_oauth(
            identity=identity,
            state=start["state"],
            authorization_code="authorization-code-secret",
        )

        self.assertEqual(result["status"], "connected")
        self.assertEqual(result["googleAccountId"], "google-account-1")
        self.assertEqual(result["redirectTarget"], "/setup")
        self.assertEqual(fixture.token_exchange.exchange_calls[0]["redirectUri"], flow.redirect_uri)
        stored = fixture.token_repository.get(
            tenant_id="tenant-1",
            user_id="user-1",
            provider="google",
            google_account_id="google-account-1",
        )
        self.assertEqual(stored["accessTokenCiphertext"], "encrypted:oauth-token:19")
        self.assertEqual(stored["refreshTokenCiphertext"], "encrypted:oauth-token:20")
        self.assertEqual(audit_sink.events[-1]["event"], "google_oauth_connected")
        self.assert_metadata_only(result)
        self.assert_metadata_only(audit_sink.events)

    def test_rejects_state_replay_wrong_user_expired_state_and_tampering(self) -> None:
        fixture = create_auth_fixture()
        flow = self.create_flow(fixture=fixture)
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        start = flow.start_google_oauth(identity=identity, redirect_target="/setup")

        flow.complete_google_oauth(
            identity=identity,
            state=start["state"],
            authorization_code="authorization-code-secret",
        )
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

        wrong_user_start = flow.start_google_oauth(identity=identity, redirect_target="/setup")
        wrong_identity = {**identity, "userId": "user-2"}
        assert_auth_error(
            self,
            lambda: flow.complete_google_oauth(
                identity=wrong_identity,
                state=wrong_user_start["state"],
                authorization_code="authorization-code-secret",
            ),
            AUTH_ERROR_CODES["OAUTH_STATE_INVALID"],
            400,
        )

        expired_flow = self.create_flow(
            fixture=fixture,
            clock_values=[
                BASE_TIME,
                datetime(2026, 5, 29, 12, 11, 0, tzinfo=timezone.utc),
            ],
        )
        expired_start = expired_flow.start_google_oauth(identity=identity, redirect_target="/setup")
        assert_auth_error(
            self,
            lambda: expired_flow.complete_google_oauth(
                identity=identity,
                state=expired_start["state"],
                authorization_code="authorization-code-secret",
            ),
            AUTH_ERROR_CODES["OAUTH_STATE_INVALID"],
            400,
        )

        assert_auth_error(
            self,
            lambda: flow.complete_google_oauth(
                identity=identity,
                state=f"{start['state']}tampered",
                authorization_code="authorization-code-secret",
            ),
            AUTH_ERROR_CODES["OAUTH_STATE_INVALID"],
            400,
        )

    def test_callback_exchange_failure_does_not_store_tokens_or_log_authorization_code(self) -> None:
        fixture = create_auth_fixture()
        fixture.token_exchange.fail_exchange = True
        audit_sink = FakeAuditSink()
        flow = self.create_flow(fixture=fixture, audit_sink=audit_sink)
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        start = flow.start_google_oauth(identity=identity, redirect_target="/setup")

        assert_auth_error(
            self,
            lambda: flow.complete_google_oauth(
                identity=identity,
                state=start["state"],
                authorization_code="authorization-code-secret",
            ),
            AUTH_ERROR_CODES["OAUTH_EXCHANGE_FAILED"],
            502,
        )

        self.assertEqual(fixture.token_repository.records, {})
        self.assert_metadata_only(audit_sink.events)

    def test_callback_exchange_failure_returns_safe_google_error_details(self) -> None:
        fixture = create_auth_fixture()
        fixture.token_exchange.exchange_exception = GoogleOAuthExchangeError(
            error_code="invalid_client",
            status=401,
        )
        flow = self.create_flow(fixture=fixture)
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        start = flow.start_google_oauth(identity=identity, redirect_target="/setup")

        with self.assertRaisesRegex(Exception, "Google OAuth code exchange failed") as caught:
            flow.complete_google_oauth(
                identity=identity,
                state=start["state"],
                authorization_code="authorization-code-secret",
            )

        self.assertEqual(caught.exception.code, AUTH_ERROR_CODES["OAUTH_EXCHANGE_FAILED"])
        self.assertEqual(caught.exception.status, 502)
        self.assertEqual(
            caught.exception.details,
            {
                "dependencyStatus": "google_token_exchange_failed",
                "googleError": "invalid_client",
                "googleStep": "unknown",
                "tokenHttpStatus": 401,
            },
        )
        self.assert_metadata_only(caught.exception.to_response())

    def test_callback_malformed_exchange_response_fails_safely_without_storing_tokens(self) -> None:
        fixture = create_auth_fixture()
        fixture.token_exchange.exchange_response = {
            "googleAccountId": "google-account-1",
            "scopes": ["https://www.googleapis.com/auth/documents"],
            "accessToken": "",
            "expiresAt": LATER_TIME,
        }
        flow = self.create_flow(fixture=fixture)
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        start = flow.start_google_oauth(identity=identity, redirect_target="/setup")

        assert_auth_error(
            self,
            lambda: flow.complete_google_oauth(
                identity=identity,
                state=start["state"],
                authorization_code="authorization-code-secret",
            ),
            AUTH_ERROR_CODES["OAUTH_EXCHANGE_FAILED"],
            502,
        )

        self.assertEqual(fixture.token_repository.records, {})

    def create_flow(
        self,
        *,
        fixture: object,
        audit_sink: FakeAuditSink | None = None,
        clock_values: list[datetime] | None = None,
    ) -> GoogleOAuthFlowService:
        state = {"nonce": 0, "clock": 0}

        def nonce_factory() -> str:
            state["nonce"] += 1
            return f"nonce-{state['nonce']}"

        def clock() -> datetime:
            if clock_values is None:
                return BASE_TIME
            index = min(state["clock"], len(clock_values) - 1)
            state["clock"] += 1
            return clock_values[index]

        return GoogleOAuthFlowService(
            oauth_token_service=fixture.oauth_token_service,
            state_repository=InMemoryOAuthStateRepository(),
            state_codec=SignedOAuthStateCodec(signing_secret="state-signing-secret"),
            token_exchange=fixture.token_exchange,
            client_id="client-1",
            redirect_uri="https://app.example.com/oauth/google/callback",
            allowed_redirect_targets=["/setup", "/dashboard"],
            nonce_factory=nonce_factory,
            clock=clock,
            audit_sink=audit_sink,
        )

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
            "bearer ",
        ]:
            self.assertNotIn(disallowed, serialized)


if __name__ == "__main__":
    unittest.main()
