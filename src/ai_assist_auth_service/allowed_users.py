from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .errors import authentication_required, forbidden, invalid_auth_token, malformed_auth_token
from .tenancy import MEMBERSHIP_STATUS, TENANT_ROLES, USER_STATUS
from .validation import require_datetime, require_non_empty_string


ALLOWED_USER_STATUS = {"ACTIVE": "active", "DISABLED": "disabled"}
DEFAULT_ALLOWED_USERS_ENV = "AI_ASSIST_ALLOWED_PRODUCT_USERS_JSON"


@dataclass(frozen=True)
class AllowedProductUser:
    auth_subject: str
    tenant_id: str
    user_id: str
    role: str
    status: str


class AllowedProductUserDirectory:
    def __init__(self, *, users: list[AllowedProductUser] | tuple[AllowedProductUser, ...]) -> None:
        self._by_subject = {user.auth_subject: user for user in users}
        if len(self._by_subject) != len(users):
            raise ValueError("Allowed product user authSubject values must be unique.")

    @classmethod
    def from_json(cls, value: str | None) -> "AllowedProductUserDirectory":
        if not value or not value.strip():
            return cls(users=[])
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as error:
            raise ValueError("AI_ASSIST_ALLOWED_PRODUCT_USERS_JSON must be valid JSON.") from error
        if not isinstance(parsed, list):
            raise ValueError("AI_ASSIST_ALLOWED_PRODUCT_USERS_JSON must be a JSON array.")
        return cls(users=[_parse_allowed_user(item) for item in parsed])

    def require_active_user(self, auth_subject: str) -> AllowedProductUser:
        subject = require_non_empty_string(auth_subject, "authSubject")
        user = self._by_subject.get(subject)
        if user is None:
            raise forbidden()
        if user.status != ALLOWED_USER_STATUS["ACTIVE"]:
            raise forbidden()
        return user

    def seed_tenant_directory(self, tenant_directory: Any) -> None:
        for user in self._by_subject.values():
            tenant_directory.put_tenant(tenant_id=user.tenant_id)
            tenant_directory.put_user(
                user_id=user.user_id,
                status=USER_STATUS["ACTIVE"] if user.status == ALLOWED_USER_STATUS["ACTIVE"] else USER_STATUS["DISABLED"],
                default_tenant_id=user.tenant_id,
            )
            tenant_directory.put_membership(
                tenant_id=user.tenant_id,
                user_id=user.user_id,
                role=user.role,
                status=MEMBERSHIP_STATUS["ACTIVE"] if user.status == ALLOWED_USER_STATUS["ACTIVE"] else MEMBERSHIP_STATUS["DISABLED"],
            )


class TrustedEdgeJwtSessionMapper:
    def __init__(
        self,
        *,
        allowed_users: AllowedProductUserDirectory,
        audience: str,
        issuer: str,
        clock: Any | None = None,
    ) -> None:
        self.allowed_users = allowed_users
        self.audience = require_non_empty_string(audience, "audience")
        self.issuer = require_non_empty_string(issuer, "issuer")
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def product_session_from_headers(self, headers: dict[str, str]) -> dict[str, Any]:
        auth_subject = _header(headers, "x-ai-assist-auth-subject")
        if not auth_subject:
            raise authentication_required("Verified product auth subject is required.")
        claims = unverified_jwt_claims(_bearer_token(headers))
        if claims.get("sub") != auth_subject:
            raise invalid_auth_token("Verified product auth subject does not match the bearer token.")
        if claims.get("iss") != self.issuer:
            raise invalid_auth_token("The product auth token has the wrong issuer.")
        if not _audience_matches(claims.get("aud"), self.audience):
            raise invalid_auth_token("The product auth token has the wrong audience.")
        expires_at = _jwt_expiration(claims)
        if expires_at <= self.clock().astimezone(timezone.utc):
            raise invalid_auth_token("The product auth token is expired.")
        allowed_user = self.allowed_users.require_active_user(auth_subject)
        return {
            "tenantId": allowed_user.tenant_id,
            "userId": allowed_user.user_id,
            "authSubject": allowed_user.auth_subject,
            "audience": self.audience,
            "sessionId": f"edge-jwt:{allowed_user.auth_subject}",
            "expiresAt": expires_at,
            "requestId": _header(headers, "x-request-id"),
            "correlationId": _header(headers, "x-correlation-id"),
        }


def unverified_jwt_claims(token: str) -> dict[str, Any]:
    try:
        _header_segment, payload_segment, _signature_segment = token.split(".")
    except ValueError:
        raise malformed_auth_token()
    try:
        payload = json.loads(base64.urlsafe_b64decode(_pad(payload_segment)).decode("utf-8"))
    except (ValueError, TypeError, json.JSONDecodeError):
        raise malformed_auth_token()
    if not isinstance(payload, dict):
        raise malformed_auth_token()
    return payload


def _parse_allowed_user(value: object) -> AllowedProductUser:
    if not isinstance(value, dict):
        raise ValueError("Allowed product users must be JSON objects.")
    role = require_non_empty_string(value.get("role", TENANT_ROLES["MEMBER"]), "role")
    if role not in set(TENANT_ROLES.values()):
        raise ValueError("Allowed product user role is not supported.")
    status = require_non_empty_string(value.get("status", ALLOWED_USER_STATUS["ACTIVE"]), "status")
    if status not in set(ALLOWED_USER_STATUS.values()):
        raise ValueError("Allowed product user status is not supported.")
    return AllowedProductUser(
        auth_subject=require_non_empty_string(value.get("authSubject"), "authSubject"),
        tenant_id=require_non_empty_string(value.get("tenantId"), "tenantId"),
        user_id=require_non_empty_string(value.get("userId"), "userId"),
        role=role,
        status=status,
    )


def _jwt_expiration(claims: dict[str, Any]) -> datetime:
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        raise malformed_auth_token()
    return require_datetime(datetime.fromtimestamp(exp, tz=timezone.utc), "exp")


def _audience_matches(value: object, expected: str) -> bool:
    if isinstance(value, str):
        return value == expected
    if isinstance(value, list):
        return expected in value
    return False


def _bearer_token(headers: dict[str, str]) -> str:
    authorization = _header(headers, "authorization")
    if not authorization or not authorization.startswith("Bearer "):
        raise authentication_required("Bearer product auth token is required.")
    return authorization[len("Bearer ") :].strip()


def _header(headers: dict[str, str], name: str) -> str | None:
    return headers.get(name.lower())


def _pad(value: str) -> bytes:
    return (value + ("=" * (-len(value) % 4))).encode("ascii")
