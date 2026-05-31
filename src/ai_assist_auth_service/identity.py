from __future__ import annotations

from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Callable

from .errors import (
    authentication_required,
    expired_auth_token,
    forbidden,
    invalid_auth_token,
    malformed_auth_token,
    validation_failed,
)
from .validation import freeze, require_datetime, require_non_empty_string, to_iso


AUTH_REFERENCE_TYPES = MappingProxyType(
    {
        "SESSION": "session",
        "RESOURCE": "resource",
        "ACTION": "action",
        "GRANT": "grant",
    }
)

_REFERENCE_ID_FIELDS = MappingProxyType(
    {
        AUTH_REFERENCE_TYPES["SESSION"]: "sessionId",
        AUTH_REFERENCE_TYPES["RESOURCE"]: "resourceId",
        AUTH_REFERENCE_TYPES["ACTION"]: "actionId",
        AUTH_REFERENCE_TYPES["GRANT"]: "grantId",
    }
)


class IdentityService:
    def __init__(
        self,
        *,
        tenant_directory: Any,
        clock: Callable[[], datetime] | None = None,
        expected_audience: str | None = None,
    ) -> None:
        if tenant_directory is None:
            raise TypeError("tenantDirectory is required.")
        self.tenant_directory = tenant_directory
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.expected_audience = expected_audience

    def derive_identity(
        self,
        *,
        product_session: dict[str, Any] | None = None,
        client_identity: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if product_session is None:
            raise authentication_required()
        if product_session.get("revokedAt") is not None:
            raise invalid_auth_token("The product auth token has been revoked.")
        if self.expected_audience and product_session.get("audience") != self.expected_audience:
            raise invalid_auth_token("The product auth token has the wrong audience.")

        try:
            expires_at = require_datetime(product_session.get("expiresAt"), "productSession.expiresAt")
            tenant_id = require_non_empty_string(product_session.get("tenantId"), "productSession.tenantId")
            user_id = require_non_empty_string(product_session.get("userId"), "productSession.userId")
            auth_subject = require_non_empty_string(
                product_session.get("authSubject"), "productSession.authSubject"
            )
        except (TypeError, ValueError):
            raise malformed_auth_token()

        if expires_at <= _as_utc(self.clock()):
            raise expired_auth_token()

        membership_summary = self.tenant_directory.summarize_membership(
            tenant_id=tenant_id, user_id=user_id
        )
        client_identity = client_identity or {}

        return freeze({
            "tenantId": tenant_id,
            "userId": user_id,
            "authSubject": auth_subject,
            "requestId": product_session.get("requestId"),
            "correlationId": product_session.get("correlationId"),
            "expiresAt": to_iso(expires_at),
            "membership": membership_summary,
            "ignoredClientIdentity": {
                "tenantId": client_identity.get("tenantId"),
                "userId": client_identity.get("userId"),
            },
        })

    def assert_same_tenant(self, identity: dict[str, Any], reference_tenant_id: str) -> bool:
        require_identity(identity)
        require_non_empty_string(reference_tenant_id, "referenceTenantId")
        if identity["tenantId"] != reference_tenant_id:
            raise forbidden()
        self.tenant_directory.assert_active_membership(
            tenant_id=identity["tenantId"], user_id=identity["userId"]
        )
        return True

    def assert_same_tenant_user(self, identity: dict[str, Any], reference: dict[str, Any] | None) -> bool:
        require_identity(identity)
        if reference is None:
            raise forbidden()
        reference_tenant_id = require_non_empty_string(reference.get("tenantId"), "reference.tenantId")
        reference_user_id = require_non_empty_string(reference.get("userId"), "reference.userId")
        if identity["tenantId"] != reference_tenant_id or identity["userId"] != reference_user_id:
            raise forbidden()
        self.tenant_directory.assert_active_membership(
            tenant_id=identity["tenantId"], user_id=identity["userId"]
        )
        return True

    def assert_authorized_reference(
        self,
        identity: dict[str, Any],
        reference: dict[str, Any] | None,
        *,
        reference_type: str | None = None,
    ) -> dict[str, Any]:
        require_identity(identity)
        id_field = _REFERENCE_ID_FIELDS.get(reference_type)
        if id_field is None:
            raise validation_failed("referenceType", "Reference type is not supported.")
        if reference is None:
            raise forbidden()

        try:
            reference_id = require_non_empty_string(reference.get(id_field), f"reference.{id_field}")
            reference_tenant_id = require_non_empty_string(reference.get("tenantId"), "reference.tenantId")
            reference_user_id = require_non_empty_string(reference.get("userId"), "reference.userId")
        except TypeError:
            raise forbidden()
        if identity["tenantId"] != reference_tenant_id or identity["userId"] != reference_user_id:
            raise forbidden()
        self.tenant_directory.assert_active_membership(
            tenant_id=identity["tenantId"], user_id=identity["userId"]
        )
        return freeze({
            "referenceType": reference_type,
            "referenceId": reference_id,
            "tenantId": reference_tenant_id,
            "userId": reference_user_id,
        })


def require_identity(identity: dict[str, Any] | None) -> None:
    if not identity or not identity.get("tenantId") or not identity.get("userId") or not identity.get(
        "authSubject"
    ):
        raise authentication_required()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
