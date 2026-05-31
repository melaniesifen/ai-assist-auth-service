from __future__ import annotations

from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

from .errors import AUTH_ERROR_CODES, AuthError, forbidden, validation_failed
from .validation import clone_datetime, require_non_empty_string, to_iso


TENANT_STATUS = MappingProxyType({"ACTIVE": "active", "DISABLED": "disabled"})
USER_STATUS = MappingProxyType({"ACTIVE": "active", "DISABLED": "disabled"})
MEMBERSHIP_STATUS = MappingProxyType({"ACTIVE": "active", "DISABLED": "disabled"})
TENANT_ROLES = MappingProxyType({"OWNER": "owner", "MEMBER": "member"})

_ALLOWED_ROLES = frozenset(TENANT_ROLES.values())


class InMemoryTenantDirectory:
    def __init__(self) -> None:
        self.tenants: dict[str, dict[str, Any]] = {}
        self.users: dict[str, dict[str, Any]] = {}
        self.memberships: dict[str, dict[str, Any]] = {}

    def put_tenant(
        self,
        *,
        tenant_id: str,
        status: str = TENANT_STATUS["ACTIVE"],
        created_at: datetime | None = None,
    ) -> dict[str, Any]:
        require_non_empty_string(tenant_id, "tenantId")
        self.tenants[tenant_id] = {
            "tenantId": tenant_id,
            "status": status,
            "createdAt": clone_datetime(created_at or _now()),
        }
        return self.get_tenant(tenant_id)

    def put_user(
        self,
        *,
        user_id: str,
        status: str = USER_STATUS["ACTIVE"],
        default_tenant_id: str | None = None,
        created_at: datetime | None = None,
    ) -> dict[str, Any]:
        require_non_empty_string(user_id, "userId")
        self.users[user_id] = {
            "userId": user_id,
            "status": status,
            "defaultTenantId": default_tenant_id,
            "createdAt": clone_datetime(created_at or _now()),
        }
        return self.get_user(user_id)

    def put_membership(
        self,
        *,
        tenant_id: str,
        user_id: str,
        role: str = TENANT_ROLES["MEMBER"],
        status: str = MEMBERSHIP_STATUS["ACTIVE"],
        created_at: datetime | None = None,
        disabled_at: datetime | None = None,
    ) -> dict[str, Any]:
        require_non_empty_string(tenant_id, "tenantId")
        require_non_empty_string(user_id, "userId")
        if role not in _ALLOWED_ROLES:
            raise validation_failed("role", "Tenant role is not supported.")
        membership = {
            "tenantId": tenant_id,
            "userId": user_id,
            "role": role,
            "status": status,
            "createdAt": clone_datetime(created_at or _now()),
            "disabledAt": clone_datetime(disabled_at),
        }
        self.memberships[_membership_key(tenant_id, user_id)] = membership
        return self.get_membership(tenant_id, user_id)

    def get_tenant(self, tenant_id: str) -> dict[str, Any] | None:
        tenant = self.tenants.get(tenant_id)
        if tenant is None:
            return None
        return {**tenant, "createdAt": clone_datetime(tenant["createdAt"])}

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        user = self.users.get(user_id)
        if user is None:
            return None
        return {**user, "createdAt": clone_datetime(user["createdAt"])}

    def get_membership(self, tenant_id: str, user_id: str) -> dict[str, Any] | None:
        membership = self.memberships.get(_membership_key(tenant_id, user_id))
        if membership is None:
            return None
        return {
            **membership,
            "createdAt": clone_datetime(membership["createdAt"]),
            "disabledAt": clone_datetime(membership["disabledAt"]),
        }

    def assert_active_membership(self, *, tenant_id: str, user_id: str) -> dict[str, Any]:
        require_non_empty_string(tenant_id, "tenantId")
        require_non_empty_string(user_id, "userId")

        tenant = self.tenants.get(tenant_id)
        if tenant is None or tenant["status"] != TENANT_STATUS["ACTIVE"]:
            raise AuthError(
                code=AUTH_ERROR_CODES["TENANT_DISABLED"],
                message="Tenant is disabled or unavailable.",
                status=403,
            )

        user = self.users.get(user_id)
        if user is None or user["status"] != USER_STATUS["ACTIVE"]:
            raise AuthError(
                code=AUTH_ERROR_CODES["USER_DISABLED"],
                message="User is disabled or unavailable.",
                status=403,
            )

        membership = self.memberships.get(_membership_key(tenant_id, user_id))
        if membership is None or membership["status"] != MEMBERSHIP_STATUS["ACTIVE"]:
            raise forbidden()

        return {
            "tenant": {**tenant, "createdAt": clone_datetime(tenant["createdAt"])},
            "user": {**user, "createdAt": clone_datetime(user["createdAt"])},
            "membership": {
                **membership,
                "createdAt": clone_datetime(membership["createdAt"]),
                "disabledAt": clone_datetime(membership["disabledAt"]),
            },
        }

    def summarize_membership(self, *, tenant_id: str, user_id: str) -> dict[str, Any]:
        membership = self.assert_active_membership(tenant_id=tenant_id, user_id=user_id)[
            "membership"
        ]
        return {
            "tenantId": tenant_id,
            "userId": user_id,
            "role": membership["role"],
            "status": membership["status"],
            "createdAt": to_iso(membership["createdAt"]),
            "disabledAt": to_iso(membership["disabledAt"]),
        }


def _membership_key(tenant_id: str, user_id: str) -> str:
    return f"{tenant_id}:{user_id}"


def _now() -> datetime:
    return datetime.now(timezone.utc)
