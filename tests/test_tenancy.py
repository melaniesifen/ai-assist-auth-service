from __future__ import annotations

import unittest

from auth_test_helpers import (  # noqa: E402
    assert_auth_error,
    create_auth_fixture,
    product_session,
)
from ai_assist_auth_service import (  # noqa: E402
    AUTH_ERROR_CODES,
    MEMBERSHIP_STATUS,
    TENANT_STATUS,
    USER_STATUS,
)


class TenancyAuthorizationTest(unittest.TestCase):
    def test_rejects_disabled_tenants_disabled_users_and_inactive_memberships(self) -> None:
        disabled_tenant = create_auth_fixture(tenant_status=TENANT_STATUS["DISABLED"])
        assert_auth_error(
            self,
            lambda: disabled_tenant.identity_service.derive_identity(
                product_session=product_session()
            ),
            AUTH_ERROR_CODES["TENANT_DISABLED"],
            403,
        )

        disabled_user = create_auth_fixture(user_status=USER_STATUS["DISABLED"])
        assert_auth_error(
            self,
            lambda: disabled_user.identity_service.derive_identity(product_session=product_session()),
            AUTH_ERROR_CODES["USER_DISABLED"],
            403,
        )

        disabled_membership = create_auth_fixture(
            membership_status=MEMBERSHIP_STATUS["DISABLED"]
        )
        assert_auth_error(
            self,
            lambda: disabled_membership.identity_service.derive_identity(
                product_session=product_session()
            ),
            AUTH_ERROR_CODES["TENANT_ACCESS_DENIED"],
            403,
        )

    def test_rejects_cross_tenant_references_without_leaking_existence(self) -> None:
        fixture = create_auth_fixture()
        identity = fixture.identity_service.derive_identity(product_session=product_session())

        assert_auth_error(
            self,
            lambda: fixture.identity_service.assert_same_tenant(identity, "tenant-2"),
            AUTH_ERROR_CODES["TENANT_ACCESS_DENIED"],
            403,
        )


if __name__ == "__main__":
    unittest.main()
