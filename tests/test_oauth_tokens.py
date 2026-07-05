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
    GOOGLE_TOKEN_HANDOFF_OPERATIONS,
    TENANT_ROLES,
    OAuthTokenService,
)


class OAuthTokenServiceTest(unittest.TestCase):
    def test_stores_google_oauth_tokens_with_encryption_context_and_metadata_only_response(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())

        metadata = fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["docs.read", "docs.read", "drive.file"],
            access_token="access-token-secret",
            refresh_token="refresh-token-secret",
            expires_at=LATER_TIME,
        )

        self.assertEqual(metadata["provider"], "google")
        self.assertEqual(metadata["status"], "active")
        self.assertEqual(metadata["scopes"], ("docs.read", "drive.file"))
        self.assertFalse(metadata["isExpired"])
        self.assertNotIn("accessToken", metadata)
        self.assertNotIn("refreshToken", metadata)
        self.assertNotIn("accessTokenCiphertext", metadata)
        self.assertEqual(len(fixture.token_protector.calls), 2)
        self.assertEqual(
            fixture.token_protector.calls[0]["context"],
            {
                "tenantId": "tenant-1",
                "userId": "user-1",
                "provider": "google",
                "purpose": "oauth-token",
            },
        )
        with self.assertRaises(TypeError):
            metadata["status"] = "revoked"
        with self.assertRaises(AttributeError):
            metadata["scopes"].append("secret.scope")

    def test_returns_status_metadata_without_exposing_token_material(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["docs.read"],
            access_token="access-token-secret",
            refresh_token="refresh-token-secret",
            expires_at=LATER_TIME,
        )

        status = fixture.oauth_token_service.get_google_status(identity=identity)

        self.assertTrue(status["connected"])
        self.assertEqual(len(status["accounts"]), 1)
        self.assertEqual(status["accounts"][0]["googleAccountId"], "google-account-1")
        serialized = json.dumps(status).lower()
        for disallowed in [
            "secret",
            "accesstoken",
            "refreshtoken",
            "authorizationcode",
            "authorizationheader",
            "authorization:",
            "ciphertext",
        ]:
            self.assertNotIn(disallowed, serialized)
        with self.assertRaises(TypeError):
            status["connected"] = False
        with self.assertRaises(TypeError):
            status["accounts"][0]["status"] = "revoked"

    def test_reports_expired_non_refreshable_google_tokens_as_reconnect_required(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["docs.read"],
            access_token="access-token-secret",
            expires_at=datetime(2026, 5, 29, 11, 59, 59, tzinfo=timezone.utc),
        )

        status = fixture.oauth_token_service.get_google_status(identity=identity)

        self.assertFalse(status["connected"])
        self.assertFalse(status["accounts"][0]["isAvailable"])
        self.assertTrue(status["accounts"][0]["reconnectRequired"])
        assert_auth_error(
            self,
            lambda: fixture.oauth_token_service.assert_google_token_usable(
                identity=identity, google_account_id="google-account-1"
            ),
            AUTH_ERROR_CODES["OAUTH_TOKEN_REVOKED"],
            403,
        )

    def test_marks_revoked_tokens_unusable_and_clears_stored_ciphertext(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["docs.read"],
            access_token="access-token-secret",
            refresh_token="refresh-token-secret",
            expires_at=LATER_TIME,
        )

        revoked = fixture.oauth_token_service.revoke_google(
            identity=identity, google_account_id="google-account-1"
        )

        self.assertEqual(revoked["status"], "revoked")
        assert_auth_error(
            self,
            lambda: fixture.oauth_token_service.assert_google_token_usable(
                identity=identity, google_account_id="google-account-1"
            ),
            AUTH_ERROR_CODES["OAUTH_TOKEN_REVOKED"],
            403,
        )
        stored = fixture.token_repository.get(
            tenant_id="tenant-1",
            user_id="user-1",
            provider="google",
            google_account_id="google-account-1",
        )
        self.assertIsNone(stored["accessTokenCiphertext"])
        self.assertIsNone(stored["refreshTokenCiphertext"])

    def test_does_not_expose_oauth_tokens_to_another_active_same_tenant_user(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["docs.read"],
            access_token="access-token-secret",
            refresh_token="refresh-token-secret",
            expires_at=LATER_TIME,
        )
        fixture.tenant_directory.put_user(
            user_id="user-2", default_tenant_id="tenant-1", created_at=BASE_TIME
        )
        fixture.tenant_directory.put_membership(
            tenant_id="tenant-1",
            user_id="user-2",
            role=TENANT_ROLES["MEMBER"],
            created_at=BASE_TIME,
        )

        other_identity = {
            "tenantId": "tenant-1",
            "userId": "user-2",
            "authSubject": "auth0|subject-2",
        }

        status = fixture.oauth_token_service.get_google_status(
            identity=other_identity, google_account_id="google-account-1"
        )

        self.assertFalse(status["connected"])
        self.assertEqual(status["accounts"], ())

    def test_preserves_existing_refresh_tokens_when_reconnecting_with_access_token_only_metadata(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["docs.read"],
            access_token="access-token-secret",
            refresh_token="refresh-token-secret",
            expires_at=LATER_TIME,
        )

        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["docs.read", "drive.file"],
            access_token="new-access-token-secret",
            expires_at=datetime(2026, 5, 29, 15, 0, 0, tzinfo=timezone.utc),
        )

        stored = fixture.token_repository.get(
            tenant_id="tenant-1",
            user_id="user-1",
            provider="google",
            google_account_id="google-account-1",
        )
        self.assertEqual(stored["refreshTokenCiphertext"], "encrypted:oauth-token:20")
        self.assertEqual(stored["scopes"], ["docs.read", "drive.file"])

    def test_returns_internal_google_token_handoff_for_read_operations(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["https://www.googleapis.com/auth/documents.readonly"],
            access_token="access-token-secret",
            refresh_token="refresh-token-secret",
            expires_at=LATER_TIME,
        )

        handoff = fixture.oauth_token_service.get_google_access_token(
            identity=identity,
            google_account_id="google-account-1",
            operation=GOOGLE_TOKEN_HANDOFF_OPERATIONS["READ_CONTEXT"],
            required_scopes=["https://www.googleapis.com/auth/documents.readonly"],
        )

        self.assertEqual(handoff["status"], "active")
        self.assertEqual(handoff["accessToken"], "access-token-secret")
        self.assertEqual(handoff["operation"], "readContext")
        self.assertEqual(
            handoff["requiredScopes"],
            ("https://www.googleapis.com/auth/documents.readonly",),
        )
        self.assertFalse(handoff["reconnectRequired"])
        self.assertNotIn("refreshToken", handoff)
        self.assertNotIn("accessTokenCiphertext", handoff)
        self.assertNotIn("refreshTokenCiphertext", handoff)
        self.assertEqual(
            fixture.token_protector.calls[-1],
            {
                "ciphertext": "encrypted:oauth-token:19",
                "context": {
                    "tenantId": "tenant-1",
                    "userId": "user-1",
                    "provider": "google",
                    "purpose": "oauth-token",
                },
            },
        )

    def test_google_token_handoff_treats_full_docs_scope_as_satisfying_readonly_scope(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=[
                "https://www.googleapis.com/auth/documents",
                "https://www.googleapis.com/auth/drive.metadata.readonly",
            ],
            access_token="access-token-secret",
            refresh_token="refresh-token-secret",
            expires_at=LATER_TIME,
        )

        handoff = fixture.oauth_token_service.get_google_access_token(
            identity=identity,
            google_account_id="google-account-1",
            operation=GOOGLE_TOKEN_HANDOFF_OPERATIONS["READ_CONTEXT"],
            required_scopes=["https://www.googleapis.com/auth/documents.readonly"],
        )

        self.assertEqual(handoff["status"], "active")
        self.assertEqual(handoff["accessToken"], "access-token-secret")
        self.assertFalse(handoff["reconnectRequired"])

    def test_google_token_handoff_returns_reconnect_required_for_unavailable_tokens(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())

        handoff = fixture.oauth_token_service.get_google_token_handoff_status(
            identity=identity,
            google_account_id="missing-account",
            operation=GOOGLE_TOKEN_HANDOFF_OPERATIONS["LIST_RESOURCES"],
            required_scopes=["https://www.googleapis.com/auth/drive.metadata.readonly"],
        )

        self.assert_reconnect_handoff(handoff, reason="unavailable")
        self.assertNotIn("accessToken", handoff)

    def test_google_token_handoff_marks_expired_refreshable_tokens_refresh_required(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["https://www.googleapis.com/auth/documents.readonly"],
            access_token="access-token-secret",
            refresh_token="refresh-token-secret",
            expires_at=datetime(2026, 5, 29, 11, 59, 59, tzinfo=timezone.utc),
        )

        handoff = fixture.oauth_token_service.get_google_token_handoff_status(
            identity=identity,
            google_account_id="google-account-1",
            operation=GOOGLE_TOKEN_HANDOFF_OPERATIONS["READ_CONTEXT"],
            required_scopes=["https://www.googleapis.com/auth/documents.readonly"],
        )

        self.assertEqual(handoff["status"], "active")
        self.assertTrue(handoff["refreshRequired"])
        self.assertFalse(handoff["reconnectRequired"])
        self.assertNotIn("accessToken", handoff)

    def test_internal_google_token_handoff_refreshes_expired_access_token(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["https://www.googleapis.com/auth/documents.readonly"],
            access_token="access-token-secret",
            refresh_token="refresh-token-secret",
            expires_at=datetime(2026, 5, 29, 11, 59, 59, tzinfo=timezone.utc),
        )

        handoff = fixture.oauth_token_service.get_google_access_token(
            identity=identity,
            google_account_id="google-account-1",
            operation=GOOGLE_TOKEN_HANDOFF_OPERATIONS["READ_CONTEXT"],
            required_scopes=["https://www.googleapis.com/auth/documents.readonly"],
        )

        self.assertEqual(handoff["status"], "active")
        self.assertEqual(handoff["accessToken"], "refreshed-access-token-secret")
        self.assertEqual(
            fixture.token_exchange.refresh_calls,
            [
                {
                    "refreshToken": "refresh-token-secret",
                    "scopes": ["https://www.googleapis.com/auth/documents.readonly"],
                }
            ],
        )

    def test_refresh_failure_marks_google_connection_reconnect_required(self) -> None:
        fixture = create_auth_fixture()
        fixture.token_exchange.fail_refresh = True
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["https://www.googleapis.com/auth/documents.readonly"],
            access_token="access-token-secret",
            refresh_token="refresh-token-secret",
            expires_at=datetime(2026, 5, 29, 11, 59, 59, tzinfo=timezone.utc),
        )

        refreshed = fixture.oauth_token_service.refresh_google_access_token(
            identity=identity,
            google_account_id="google-account-1",
        )

        self.assertEqual(refreshed["status"], "revoked")
        self.assertIsNone(refreshed["accessTokenCiphertext"])
        self.assertIsNone(refreshed["refreshTokenCiphertext"])
        status = fixture.oauth_token_service.get_google_token_handoff_status(
            identity=identity,
            google_account_id="google-account-1",
            operation=GOOGLE_TOKEN_HANDOFF_OPERATIONS["READ_CONTEXT"],
            required_scopes=["https://www.googleapis.com/auth/documents.readonly"],
        )
        self.assert_reconnect_handoff(status, reason="revoked")

    def test_internal_google_token_handoff_returns_reconnect_when_refresh_fails(self) -> None:
        fixture = create_auth_fixture()
        fixture.token_exchange.fail_refresh = True
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["https://www.googleapis.com/auth/documents.readonly"],
            access_token="access-token-secret",
            refresh_token="refresh-token-secret",
            expires_at=datetime(2026, 5, 29, 11, 59, 59, tzinfo=timezone.utc),
        )

        handoff = fixture.oauth_token_service.get_google_access_token(
            identity=identity,
            google_account_id="google-account-1",
            operation=GOOGLE_TOKEN_HANDOFF_OPERATIONS["READ_CONTEXT"],
            required_scopes=["https://www.googleapis.com/auth/documents.readonly"],
        )

        self.assert_reconnect_handoff(handoff, reason="revoked")
        self.assertNotIn("accessToken", handoff)

    def test_revoked_refresh_response_marks_google_connection_reconnect_required(self) -> None:
        fixture = create_auth_fixture()
        fixture.token_exchange.refresh_response = {"error": "invalid_grant", "revoked": True}
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["https://www.googleapis.com/auth/documents.readonly"],
            access_token="access-token-secret",
            refresh_token="refresh-token-secret",
            expires_at=datetime(2026, 5, 29, 11, 59, 59, tzinfo=timezone.utc),
        )

        refreshed = fixture.oauth_token_service.refresh_google_access_token(
            identity=identity,
            google_account_id="google-account-1",
        )

        self.assertEqual(refreshed["status"], "revoked")
        self.assertIsNone(refreshed["accessTokenCiphertext"])

    def test_token_protector_decrypt_failure_during_refresh_fails_closed(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["https://www.googleapis.com/auth/documents.readonly"],
            access_token="access-token-secret",
            refresh_token="refresh-token-secret",
            expires_at=datetime(2026, 5, 29, 11, 59, 59, tzinfo=timezone.utc),
        )
        fixture.token_protector.ciphertexts.clear()

        refreshed = fixture.oauth_token_service.refresh_google_access_token(
            identity=identity,
            google_account_id="google-account-1",
        )

        self.assertEqual(refreshed["status"], "revoked")
        self.assertIsNone(refreshed["accessTokenCiphertext"])
        self.assertEqual(fixture.token_exchange.refresh_calls, [])

    def test_disconnect_google_revokes_and_clears_token_material(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["https://www.googleapis.com/auth/documents.readonly"],
            access_token="access-token-secret",
            refresh_token="refresh-token-secret",
            expires_at=LATER_TIME,
        )

        disconnected = fixture.oauth_token_service.disconnect_google(
            identity=identity,
            google_account_id="google-account-1",
        )

        self.assertEqual(disconnected["status"], "revoked")
        self.assertTrue(disconnected["reconnectRequired"])
        stored = fixture.token_repository.get(
            tenant_id="tenant-1",
            user_id="user-1",
            provider="google",
            google_account_id="google-account-1",
        )
        self.assertIsNone(stored["accessTokenCiphertext"])
        self.assertIsNone(stored["refreshTokenCiphertext"])

    def test_google_token_handoff_returns_reconnect_required_for_revoked_tokens(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["https://www.googleapis.com/auth/documents.readonly"],
            access_token="access-token-secret",
            refresh_token="refresh-token-secret",
            expires_at=LATER_TIME,
        )
        fixture.oauth_token_service.revoke_google(
            identity=identity,
            google_account_id="google-account-1",
        )

        handoff = fixture.oauth_token_service.get_google_access_token(
            identity=identity,
            google_account_id="google-account-1",
            operation=GOOGLE_TOKEN_HANDOFF_OPERATIONS["READ_CONTEXT"],
            required_scopes=["https://www.googleapis.com/auth/documents.readonly"],
        )

        self.assert_reconnect_handoff(handoff, reason="revoked")
        self.assertNotIn("accessToken", handoff)

    def test_google_token_handoff_returns_reconnect_required_for_insufficient_scopes(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        fixture.oauth_token_service.connect_google(
            identity=identity,
            google_account_id="google-account-1",
            scopes=["https://www.googleapis.com/auth/drive.metadata.readonly"],
            access_token="access-token-secret",
            refresh_token="refresh-token-secret",
            expires_at=LATER_TIME,
        )

        handoff = fixture.oauth_token_service.get_google_access_token(
            identity=identity,
            google_account_id="google-account-1",
            operation=GOOGLE_TOKEN_HANDOFF_OPERATIONS["READ_CONTEXT"],
            required_scopes=["https://www.googleapis.com/auth/documents.readonly"],
        )

        self.assert_reconnect_handoff(handoff, reason="insufficient_scope")
        self.assertEqual(
            handoff["error"]["details"],
            {"missingScopes": ("https://www.googleapis.com/auth/documents.readonly",)},
        )
        self.assertNotIn("accessToken", handoff)

    def test_validates_oauth_service_constructor_dependencies_and_required_token_inputs(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())

        with self.assertRaises(TypeError):
            OAuthTokenService(
                tenant_directory=None,
                token_repository=fixture.token_repository,
                token_protector=fixture.token_protector,
            )
        with self.assertRaises(TypeError):
            OAuthTokenService(
                tenant_directory=fixture.tenant_directory,
                token_repository=None,
                token_protector=fixture.token_protector,
            )
        with self.assertRaises(TypeError):
            OAuthTokenService(
                tenant_directory=fixture.tenant_directory,
                token_repository=fixture.token_repository,
                token_protector=None,
            )
        assert_auth_error(
            self,
            lambda: fixture.oauth_token_service.connect_google(
                identity=identity,
                google_account_id="google-account-1",
                scopes=[],
                access_token="access-token-secret",
                expires_at=LATER_TIME,
            ),
            AUTH_ERROR_CODES["VALIDATION_FAILED"],
            400,
        )
        assert_auth_error(
            self,
            lambda: fixture.oauth_token_service.get_google_access_token(
                identity=identity,
                google_account_id="google-account-1",
                operation="deleteEverything",
                required_scopes=["docs.read"],
            ),
            AUTH_ERROR_CODES["VALIDATION_FAILED"],
            400,
        )
        assert_auth_error(
            self,
            lambda: fixture.oauth_token_service.connect_google(
                identity=identity,
                google_account_id="",
                scopes=["docs.read"],
                access_token="access-token-secret",
                expires_at=LATER_TIME,
            ),
            AUTH_ERROR_CODES["VALIDATION_FAILED"],
            400,
        )
        assert_auth_error(
            self,
            lambda: fixture.oauth_token_service.connect_google(
                identity=identity,
                google_account_id="google-account-1",
                scopes=["docs.read"],
                access_token="  ",
                expires_at=LATER_TIME,
            ),
            AUTH_ERROR_CODES["VALIDATION_FAILED"],
            400,
        )
        assert_auth_error(
            self,
            lambda: fixture.oauth_token_service.connect_google(
                identity=identity,
                google_account_id="google-account-1",
                scopes=["docs.read"],
                access_token="access-token-secret",
                expires_at="not-a-date",
            ),
            AUTH_ERROR_CODES["VALIDATION_FAILED"],
            400,
        )
        assert_auth_error(
            self,
            lambda: fixture.oauth_token_service.connect_google(
                identity=identity,
                google_account_id="google-account-1",
                scopes=["   "],
                access_token="access-token-secret",
                expires_at=LATER_TIME,
            ),
            AUTH_ERROR_CODES["VALIDATION_FAILED"],
            400,
        )

    def test_rejects_missing_oauth_token_references_before_downstream_use_or_revocation(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())

        assert_auth_error(
            self,
            lambda: fixture.oauth_token_service.assert_google_token_usable(
                identity=identity, google_account_id="missing-account"
            ),
            AUTH_ERROR_CODES["OAUTH_TOKEN_NOT_FOUND"],
            403,
        )
        assert_auth_error(
            self,
            lambda: fixture.oauth_token_service.revoke_google(
                identity=identity, google_account_id="missing-account"
            ),
            AUTH_ERROR_CODES["TENANT_ACCESS_DENIED"],
            403,
        )

    def assert_reconnect_handoff(self, handoff: object, *, reason: str) -> None:
        self.assertEqual(handoff["status"], "reconnect_required")
        self.assertTrue(handoff["reconnectRequired"])
        self.assertFalse(handoff["refreshRequired"])
        self.assertEqual(handoff["error"]["code"], "OAUTH_RECONNECT_REQUIRED")
        self.assertEqual(handoff["error"]["category"], "OAUTH")
        self.assertEqual(handoff["error"]["httpStatus"], 401)
        self.assertEqual(handoff["error"]["target"], "googleOAuth")
        self.assertEqual(handoff["error"]["reason"], reason)
        self.assertNotIn("authorization", json.dumps(handoff).lower())
        self.assertNotIn("ciphertext", json.dumps(handoff).lower())


if __name__ == "__main__":
    unittest.main()
