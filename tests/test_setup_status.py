from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from auth_test_helpers import (  # noqa: E402
    BASE_TIME,
    LATER_TIME,
    create_auth_fixture,
    product_session,
)
from ai_assist_auth_service import (  # noqa: E402
    GOOGLE_OAUTH_CONNECTION_STATUSES,
    PRODUCT_SESSION_STATUSES,
    SETUP_ERROR_KINDS,
    AuthSetupStatusService,
)


class AuthSetupStatusServiceTest(unittest.TestCase):
    def test_reports_authenticated_session_and_disconnected_google_oauth_metadata(self) -> None:
        fixture = create_auth_fixture()

        status = fixture.setup_status_service.get_setup_status(
            product_session=product_session(),
            client_identity={"tenantId": "attacker-tenant", "userId": "attacker-user"},
        )

        self.assertEqual(
            status["productSession"]["status"],
            PRODUCT_SESSION_STATUSES["AUTHENTICATED"],
        )
        self.assertEqual(status["productSession"]["tenantId"], "tenant-1")
        self.assertEqual(status["productSession"]["userId"], "user-1")
        self.assertEqual(status["productSession"]["sessionId"], "session-1")
        self.assertEqual(
            status["googleOAuth"]["status"],
            GOOGLE_OAUTH_CONNECTION_STATUSES["NOT_CONNECTED"],
        )
        self.assertEqual(status["errors"], ())
        self.assert_not_sensitive(status)
        with self.assertRaises(TypeError):
            status["productSession"]["tenantId"] = "attacker-tenant"

    def test_reports_connected_google_oauth_as_contract_compatible_metadata(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["https://www.googleapis.com/auth/documents"],
            access_token="access-token-secret",
            refresh_token="refresh-token-secret",
            expires_at=LATER_TIME,
        )

        status = fixture.setup_status_service.get_setup_status(
            product_session=product_session()
        )

        self.assertEqual(
            status["googleOAuth"],
            {
                "provider": "google",
                "status": GOOGLE_OAUTH_CONNECTION_STATUSES["CONNECTED"],
                "googleAccountId": "google-account-1",
                "scopes": ("https://www.googleapis.com/auth/documents",),
                "connectedAt": "2026-05-29T12:00:00.000Z",
                "expiresAt": "2026-05-29T13:00:00.000Z",
            },
        )
        self.assertEqual(status["errors"], ())
        self.assert_not_sensitive(status)

    def test_reports_reconnect_required_for_expired_or_revoked_google_oauth(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["https://www.googleapis.com/auth/documents"],
            access_token="access-token-secret",
            expires_at=datetime(2026, 5, 29, 11, 59, 59, tzinfo=timezone.utc),
        )

        status = fixture.setup_status_service.get_setup_status(
            product_session=product_session()
        )

        self.assertEqual(
            status["googleOAuth"]["status"],
            GOOGLE_OAUTH_CONNECTION_STATUSES["RECONNECT_REQUIRED"],
        )
        self.assertEqual(status["googleOAuth"]["googleAccountId"], "google-account-1")
        self.assertEqual(status["googleOAuth"]["error"]["code"], "OAUTH_RECONNECT_REQUIRED")
        self.assertEqual(
            status["errors"][0]["kind"],
            SETUP_ERROR_KINDS["GOOGLE_OAUTH_RECONNECT_REQUIRED"],
        )
        self.assert_not_sensitive(status)

    def test_reports_missing_expired_and_malformed_product_sessions_without_oauth_token_lookup(self) -> None:
        fixture = create_auth_fixture()
        cases = [
            (
                None,
                PRODUCT_SESSION_STATUSES["ANONYMOUS"],
                "AUTHENTICATION_REQUIRED",
                SETUP_ERROR_KINDS["PRODUCT_SESSION_REQUIRED"],
            ),
            (
                product_session(expiresAt=datetime(2026, 5, 29, 11, 0, 0, tzinfo=timezone.utc)),
                PRODUCT_SESSION_STATUSES["EXPIRED"],
                "AUTHENTICATION_EXPIRED",
                SETUP_ERROR_KINDS["PRODUCT_SESSION_EXPIRED"],
            ),
            (
                product_session(authSubject=""),
                PRODUCT_SESSION_STATUSES["ANONYMOUS"],
                "MALFORMED_PRODUCT_CREDENTIAL",
                SETUP_ERROR_KINDS["PRODUCT_SESSION_REQUIRED"],
            ),
            (
                product_session(sessionId=""),
                PRODUCT_SESSION_STATUSES["ANONYMOUS"],
                "MALFORMED_PRODUCT_CREDENTIAL",
                SETUP_ERROR_KINDS["PRODUCT_SESSION_REQUIRED"],
            ),
        ]

        for product_session_ref, expected_status, expected_code, expected_kind in cases:
            status = fixture.setup_status_service.get_setup_status(
                product_session=product_session_ref
            )

            self.assertEqual(status["productSession"]["status"], expected_status)
            self.assertEqual(status["productSession"]["error"]["code"], expected_code)
            self.assertEqual(status["googleOAuth"]["status"], "not_connected")
            self.assertEqual(status["errors"][0]["kind"], expected_kind)
            self.assertEqual(fixture.token_repository.records, {})
            self.assert_not_sensitive(status)

    def test_reports_unauthorized_product_session_as_safe_metadata_only_status(self) -> None:
        fixture = create_auth_fixture(membership_status="disabled")

        status = fixture.setup_status_service.get_setup_status(
            product_session=product_session()
        )

        self.assertEqual(
            status["productSession"]["status"],
            PRODUCT_SESSION_STATUSES["ANONYMOUS"],
        )
        self.assertEqual(status["productSession"]["error"]["code"], "AUTHORIZATION_DENIED")
        self.assertEqual(status["productSession"]["error"]["httpStatus"], 403)
        self.assertEqual(status["googleOAuth"]["status"], "not_connected")
        self.assert_not_sensitive(status)

    def test_validates_setup_status_service_constructor_dependencies(self) -> None:
        fixture = create_auth_fixture()

        with self.assertRaises(TypeError):
            AuthSetupStatusService(
                identity_service=None,
                oauth_token_service=fixture.oauth_token_service,
            )
        with self.assertRaises(TypeError):
            AuthSetupStatusService(
                identity_service=fixture.identity_service,
                oauth_token_service=None,
            )

    def assert_not_sensitive(self, status: object) -> None:
        serialized = json.dumps(status)
        for disallowed in [
            "access-token",
            "refresh-token",
            "accessToken",
            "refreshToken",
            "accessTokenCiphertext",
            "refreshTokenCiphertext",
            "secret",
            "ciphertext",
        ]:
            self.assertNotIn(disallowed, serialized)


if __name__ == "__main__":
    unittest.main()
