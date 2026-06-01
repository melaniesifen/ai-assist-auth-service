from __future__ import annotations

import unittest
from datetime import datetime, timezone

from auth_test_helpers import (  # noqa: E402
    BASE_TIME,
    assert_auth_error,
    create_auth_fixture,
    product_session,
)
from ai_assist_auth_service import (  # noqa: E402
    AUTH_ERROR_CODES,
    AUTH_REFERENCE_TYPES,
    TENANT_ROLES,
)


class IdentityServiceTest(unittest.TestCase):
    def test_derives_identity_from_product_session_and_records_ignored_client_identity(self) -> None:
        fixture = create_auth_fixture()

        identity = fixture.identity_service.derive_identity(
            product_session=product_session(),
            client_identity={"tenantId": "attacker-tenant", "userId": "attacker-user"},
        )

        self.assertEqual(identity["tenantId"], "tenant-1")
        self.assertEqual(identity["userId"], "user-1")
        self.assertEqual(identity["authSubject"], "auth0|subject-1")
        self.assertEqual(identity["membership"]["role"], TENANT_ROLES["OWNER"])
        self.assertEqual(
            identity["ignoredClientIdentity"],
            {"tenantId": "attacker-tenant", "userId": "attacker-user"},
        )
        with self.assertRaises(TypeError):
            identity["tenantId"] = "mutated-tenant"
        with self.assertRaises(TypeError):
            identity["membership"]["role"] = TENANT_ROLES["MEMBER"]

    def test_rejects_missing_and_expired_product_sessions_with_distinct_typed_errors(self) -> None:
        fixture = create_auth_fixture()

        assert_auth_error(
            self,
            lambda: fixture.identity_service.derive_identity(),
            AUTH_ERROR_CODES["AUTHENTICATION_REQUIRED"],
            401,
        )
        assert_auth_error(
            self,
            lambda: fixture.identity_service.derive_identity(
                product_session=product_session(
                    expiresAt=datetime(2026, 5, 29, 11, 0, 0, tzinfo=timezone.utc)
                )
            ),
            AUTH_ERROR_CODES["AUTH_TOKEN_EXPIRED"],
            401,
        )

    def test_rejects_malformed_product_session_claims_with_distinct_typed_errors(self) -> None:
        fixture = create_auth_fixture()
        malformed_sessions = [
            product_session(tenantId=""),
            product_session(userId="   "),
            product_session(authSubject=None),
            product_session(expiresAt="not-a-date"),
        ]

        for malformed_session in malformed_sessions:
            assert_auth_error(
                self,
                lambda malformed_session=malformed_session: fixture.identity_service.derive_identity(
                    product_session=malformed_session
                ),
                AUTH_ERROR_CODES["AUTH_TOKEN_MALFORMED"],
                401,
            )

    def test_rejects_revoked_and_wrong_audience_product_sessions(self) -> None:
        fixture = create_auth_fixture()

        assert_auth_error(
            self,
            lambda: fixture.identity_service.derive_identity(
                product_session=product_session(revokedAt=BASE_TIME)
            ),
            AUTH_ERROR_CODES["INVALID_AUTH_TOKEN"],
            401,
        )
        assert_auth_error(
            self,
            lambda: fixture.identity_service.derive_identity(
                product_session=product_session(audience="other-app")
            ),
            AUTH_ERROR_CODES["INVALID_AUTH_TOKEN"],
            401,
        )

    def test_authorizes_client_supplied_references_as_same_user_records(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())
        references = [
            (
                AUTH_REFERENCE_TYPES["SESSION"],
                {"sessionId": "session-1", "tenantId": "tenant-1", "userId": "user-1"},
                "session-1",
            ),
            (
                AUTH_REFERENCE_TYPES["RESOURCE"],
                {"resourceId": "resource-1", "tenantId": "tenant-1", "userId": "user-1"},
                "resource-1",
            ),
            (
                AUTH_REFERENCE_TYPES["ACTION"],
                {"actionId": "action-1", "tenantId": "tenant-1", "userId": "user-1"},
                "action-1",
            ),
            (
                AUTH_REFERENCE_TYPES["GRANT"],
                {"grantId": "grant-1", "tenantId": "tenant-1", "userId": "user-1"},
                "grant-1",
            ),
        ]

        for reference_type, reference, reference_id in references:
            result = fixture.identity_service.assert_authorized_reference(
                identity, reference, reference_type=reference_type
            )

            self.assertEqual(
                result,
                {
                    "referenceType": reference_type,
                    "referenceId": reference_id,
                    "tenantId": "tenant-1",
                    "userId": "user-1",
                },
            )
            with self.assertRaises(TypeError):
                result["tenantId"] = "tenant-2"

    def test_rejects_missing_cross_tenant_cross_user_and_unsupported_references(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())

        assert_auth_error(
            self,
            lambda: fixture.identity_service.assert_authorized_reference(
                identity, None, reference_type=AUTH_REFERENCE_TYPES["SESSION"]
            ),
            AUTH_ERROR_CODES["TENANT_ACCESS_DENIED"],
            403,
        )
        assert_auth_error(
            self,
            lambda: fixture.identity_service.assert_authorized_reference(
                identity,
                {"sessionId": "session-1", "tenantId": "tenant-2", "userId": "user-1"},
                reference_type=AUTH_REFERENCE_TYPES["SESSION"],
            ),
            AUTH_ERROR_CODES["TENANT_ACCESS_DENIED"],
            403,
        )
        assert_auth_error(
            self,
            lambda: fixture.identity_service.assert_authorized_reference(
                identity,
                {"tenantId": "tenant-1", "userId": "user-1"},
                reference_type=AUTH_REFERENCE_TYPES["SESSION"],
            ),
            AUTH_ERROR_CODES["TENANT_ACCESS_DENIED"],
            403,
        )
        assert_auth_error(
            self,
            lambda: fixture.identity_service.assert_authorized_reference(
                identity,
                {"sessionId": "session-1", "userId": "user-1"},
                reference_type=AUTH_REFERENCE_TYPES["SESSION"],
            ),
            AUTH_ERROR_CODES["TENANT_ACCESS_DENIED"],
            403,
        )
        assert_auth_error(
            self,
            lambda: fixture.identity_service.assert_authorized_reference(
                identity,
                {"sessionId": "session-1", "tenantId": "tenant-1"},
                reference_type=AUTH_REFERENCE_TYPES["SESSION"],
            ),
            AUTH_ERROR_CODES["TENANT_ACCESS_DENIED"],
            403,
        )
        assert_auth_error(
            self,
            lambda: fixture.identity_service.assert_authorized_reference(
                identity,
                {"resourceId": "resource-1", "tenantId": "tenant-1", "userId": "user-2"},
                reference_type=AUTH_REFERENCE_TYPES["RESOURCE"],
            ),
            AUTH_ERROR_CODES["TENANT_ACCESS_DENIED"],
            403,
        )
        assert_auth_error(
            self,
            lambda: fixture.identity_service.assert_authorized_reference(
                identity,
                {"connectorId": "connector-1", "tenantId": "tenant-1", "userId": "user-1"},
                reference_type="connector",
            ),
            AUTH_ERROR_CODES["VALIDATION_FAILED"],
            400,
        )


if __name__ == "__main__":
    unittest.main()
