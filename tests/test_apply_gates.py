from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from auth_test_helpers import (  # noqa: E402
    BASE_TIME,
    LATER_TIME,
    assert_auth_error,
    create_auth_fixture,
    product_session,
)
from ai_assist_auth_service import (  # noqa: E402
    AUTH_ERROR_CODES,
    AUTH_REFERENCE_TYPES,
    GOOGLE_TOKEN_HANDOFF_OPERATIONS,
    USER_STATUS,
)


APPLY_GOOGLE_DOCS_SCOPE = "https://www.googleapis.com/auth/documents"


class ApplyGateAuthServiceTest(unittest.TestCase):
    def test_apply_identity_rejects_untrusted_product_session_states(self) -> None:
        cases = [
            (None, AUTH_ERROR_CODES["AUTHENTICATION_REQUIRED"]),
            (
                product_session(
                    expiresAt=datetime(2026, 5, 29, 11, 59, 59, tzinfo=timezone.utc)
                ),
                AUTH_ERROR_CODES["AUTH_TOKEN_EXPIRED"],
            ),
            (product_session(revokedAt=BASE_TIME), AUTH_ERROR_CODES["INVALID_AUTH_TOKEN"]),
            (product_session(authSubject=""), AUTH_ERROR_CODES["AUTH_TOKEN_MALFORMED"]),
            (product_session(audience="wrong-audience"), AUTH_ERROR_CODES["INVALID_AUTH_TOKEN"]),
        ]

        for session, expected_code in cases:
            fixture = create_auth_fixture()
            assert_auth_error(
                self,
                lambda session=session, fixture=fixture: fixture.identity_service.derive_identity(
                    product_session=session
                ),
                expected_code,
                401,
            )

        disabled_user = create_auth_fixture(user_status=USER_STATUS["DISABLED"])
        assert_auth_error(
            self,
            lambda: disabled_user.identity_service.derive_identity(
                product_session=product_session()
            ),
            AUTH_ERROR_CODES["USER_DISABLED"],
            403,
        )

    def test_apply_references_use_server_derived_identity_and_reject_cross_tenant_records(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(
            product_session=product_session(),
            client_identity={"tenantId": "attacker-tenant", "userId": "attacker-user"},
        )

        self.assertEqual(identity["tenantId"], "tenant-1")
        self.assertEqual(identity["userId"], "user-1")
        for reference_type, id_field in [
            (AUTH_REFERENCE_TYPES["SESSION"], "sessionId"),
            (AUTH_REFERENCE_TYPES["RESOURCE"], "resourceId"),
            (AUTH_REFERENCE_TYPES["ACTION"], "actionId"),
        ]:
            authorized = fixture.identity_service.assert_authorized_reference(
                identity,
                {id_field: f"{reference_type}-1", "tenantId": "tenant-1", "userId": "user-1"},
                reference_type=reference_type,
            )
            self.assertEqual(authorized["tenantId"], "tenant-1")
            self.assertEqual(authorized["userId"], "user-1")

            assert_auth_error(
                self,
                lambda reference_type=reference_type, id_field=id_field: (
                    fixture.identity_service.assert_authorized_reference(
                        identity,
                        {
                            id_field: f"{reference_type}-other",
                            "tenantId": "tenant-2",
                            "userId": "user-1",
                        },
                        reference_type=reference_type,
                    )
                ),
                AUTH_ERROR_CODES["TENANT_ACCESS_DENIED"],
                403,
            )

    def test_apply_google_token_status_is_metadata_only_and_does_not_decrypt_tokens(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=[APPLY_GOOGLE_DOCS_SCOPE],
            access_token="access-token-secret",
            refresh_token="refresh-token-secret",
            expires_at=LATER_TIME,
        )
        encrypt_call_count = len(fixture.token_protector.calls)

        status = fixture.oauth_token_service.get_google_token_handoff_status(
            identity=identity,
            google_account_id="google-account-1",
            operation=GOOGLE_TOKEN_HANDOFF_OPERATIONS["APPLY_ACTION"],
            required_scopes=[APPLY_GOOGLE_DOCS_SCOPE],
        )

        self.assertEqual(status["status"], "active")
        self.assertEqual(status["operation"], "applyAction")
        self.assertFalse(status["reconnectRequired"])
        self.assertEqual(len(fixture.token_protector.calls), encrypt_call_count)
        self.assert_metadata_only(status)

        assert_auth_error(
            self,
            lambda: fixture.oauth_token_service.get_google_access_token(
                identity=identity,
                google_account_id="google-account-1",
                operation=GOOGLE_TOKEN_HANDOFF_OPERATIONS["APPLY_ACTION"],
                required_scopes=[APPLY_GOOGLE_DOCS_SCOPE],
            ),
            AUTH_ERROR_CODES["VALIDATION_FAILED"],
            400,
        )

    def test_apply_google_token_status_returns_safe_reconnect_required_results(self) -> None:
        reconnect_cases = [
            ("missing", None, "unavailable"),
            (
                "expired",
                {
                    "scopes": [APPLY_GOOGLE_DOCS_SCOPE],
                    "expires_at": datetime(2026, 5, 29, 11, 59, 59, tzinfo=timezone.utc),
                    "revoke": False,
                },
                "expired",
            ),
            (
                "revoked",
                {"scopes": [APPLY_GOOGLE_DOCS_SCOPE], "expires_at": LATER_TIME, "revoke": True},
                "revoked",
            ),
            (
                "insufficient_scope",
                {
                    "scopes": ["https://www.googleapis.com/auth/drive.metadata.readonly"],
                    "expires_at": LATER_TIME,
                    "revoke": False,
                },
                "insufficient_scope",
            ),
        ]

        for label, setup, expected_reason in reconnect_cases:
            fixture = create_auth_fixture()
            identity = fixture.identity_service.derive_identity(product_session=product_session())
            if setup is not None:
                fixture.oauth_token_service.connect_google(
                    identity=identity,
                    google_account_id="google-account-1",
                    scopes=setup["scopes"],
                    access_token=f"{label}-access-token-secret",
                    refresh_token=None,
                    expires_at=setup["expires_at"],
                )
                if setup["revoke"]:
                    fixture.oauth_token_service.revoke_google(
                        identity=identity,
                        google_account_id="google-account-1",
                    )

            status = fixture.oauth_token_service.get_google_token_handoff_status(
                identity=identity,
                google_account_id="google-account-1",
                operation=GOOGLE_TOKEN_HANDOFF_OPERATIONS["APPLY_ACTION"],
                required_scopes=[APPLY_GOOGLE_DOCS_SCOPE],
            )

            self.assertEqual(status["status"], "reconnect_required")
            self.assertTrue(status["reconnectRequired"])
            self.assertEqual(status["error"]["code"], "OAUTH_RECONNECT_REQUIRED")
            self.assertEqual(status["error"]["reason"], expected_reason)
            self.assert_metadata_only(status)

    def assert_metadata_only(self, payload: object) -> None:
        serialized = json.dumps(payload).lower()
        for disallowed in [
            "access-token-secret",
            "refresh-token-secret",
            "accesstoken",
            "refreshtoken",
            "authorizationcode",
            "authorizationheader",
            "authorization:",
            "bearer ",
            "ciphertext",
            "document text",
            "selected text",
            "replacement text",
            "encryptedpayload",
        ]:
            self.assertNotIn(disallowed, serialized)


if __name__ == "__main__":
    unittest.main()
