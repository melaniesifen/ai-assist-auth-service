from __future__ import annotations

import unittest

from auth_test_helpers import (  # noqa: E402
    BASE_TIME,
    assert_auth_error,
    create_auth_fixture,
    product_session,
)
from ai_assist_auth_service import (  # noqa: E402
    AUTH_ERROR_CODES,
    AuthError,
    IdentityService,
    require_identity,
)


class ValidationAndErrorTest(unittest.TestCase):
    def test_validates_dependencies_and_same_tenant_user_references(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())

        with self.assertRaises(TypeError):
            IdentityService(tenant_directory=None)
        assert_auth_error(
            self,
            lambda: fixture.tenant_directory.put_membership(
                tenant_id="tenant-1", user_id="user-1", role="admin", created_at=BASE_TIME
            ),
            AUTH_ERROR_CODES["VALIDATION_FAILED"],
            400,
        )
        self.assertTrue(
            fixture.identity_service.assert_same_tenant_user(
                identity, {"tenantId": "tenant-1", "userId": "user-1"}
            )
        )
        assert_auth_error(
            self,
            lambda: fixture.identity_service.assert_same_tenant_user(identity, None),
            AUTH_ERROR_CODES["TENANT_ACCESS_DENIED"],
            403,
        )
        assert_auth_error(
            self,
            lambda: require_identity({"tenantId": "tenant-1", "userId": "user-1"}),
            AUTH_ERROR_CODES["AUTHENTICATION_REQUIRED"],
            401,
        )

    def test_returns_typed_response_envelopes_for_auth_error_instances(self) -> None:
        error = AuthError(
            code=AUTH_ERROR_CODES["VALIDATION_FAILED"],
            message="Request failed validation.",
            status=400,
            details={"field": "example"},
        )

        self.assertEqual(
            error.to_response(),
            {
                "error": {
                    "code": AUTH_ERROR_CODES["VALIDATION_FAILED"],
                    "message": "Request failed validation.",
                    "details": {"field": "example"},
                },
                "status": 400,
            },
        )


if __name__ == "__main__":
    unittest.main()
