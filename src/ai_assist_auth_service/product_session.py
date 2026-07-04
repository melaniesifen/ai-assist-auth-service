from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from .errors import invalid_auth_token, malformed_auth_token
from .validation import require_datetime, require_non_empty_string, to_iso


class InMemorySessionRevocationRepository:
    def __init__(self) -> None:
        self.revoked: set[str] = set()

    def revoke(self, session_id: str) -> None:
        self.revoked.add(require_non_empty_string(session_id, "sessionId"))

    def is_revoked(self, session_id: str) -> bool:
        return session_id in self.revoked


class HmacProductSessionCodec:
    def __init__(
        self,
        *,
        signing_secret: str,
        audience: str,
        ttl: timedelta = timedelta(hours=8),
        revocations: InMemorySessionRevocationRepository | None = None,
    ) -> None:
        self.signing_secret = require_non_empty_string(signing_secret, "signingSecret").encode("utf-8")
        self.audience = require_non_empty_string(audience, "audience")
        self.ttl = ttl
        self.revocations = revocations or InMemorySessionRevocationRepository()

    def issue(
        self,
        *,
        tenant_id: str,
        user_id: str,
        auth_subject: str,
        request_id: str | None = None,
        correlation_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        issued_at = now or datetime.now(timezone.utc)
        session_id = secrets.token_urlsafe(24)
        payload = {
            "tenantId": require_non_empty_string(tenant_id, "tenantId"),
            "userId": require_non_empty_string(user_id, "userId"),
            "authSubject": require_non_empty_string(auth_subject, "authSubject"),
            "audience": self.audience,
            "sessionId": session_id,
            "expiresAt": to_iso(issued_at + self.ttl),
            "requestId": request_id,
            "correlationId": correlation_id,
        }
        return {"token": self._sign(payload), "productSession": payload}

    def verify_bearer(self, authorization: str | None) -> dict[str, Any]:
        if not authorization or not authorization.startswith("Bearer "):
            raise invalid_auth_token("Bearer product session token is required.")
        return self.verify(authorization[len("Bearer ") :].strip())

    def verify(self, token: str) -> dict[str, Any]:
        try:
            encoded_header, encoded_payload, encoded_signature = token.split(".")
        except ValueError:
            raise malformed_auth_token()
        expected = hmac.new(
            self.signing_secret,
            f"{encoded_header}.{encoded_payload}".encode("ascii"),
            hashlib.sha256,
        )
        if not hmac.compare_digest(_urlsafe_bytes(expected.digest()), encoded_signature):
            raise invalid_auth_token("The product session signature is invalid.")
        try:
            payload = json.loads(base64.urlsafe_b64decode(_pad(encoded_payload)).decode("utf-8"))
        except (ValueError, TypeError, json.JSONDecodeError):
            raise malformed_auth_token()
        if not isinstance(payload, dict):
            raise malformed_auth_token()
        if payload.get("audience") != self.audience:
            raise invalid_auth_token("The product auth token has the wrong audience.")
        session_id = require_non_empty_string(payload.get("sessionId"), "sessionId")
        if self.revocations.is_revoked(session_id):
            payload = {**payload, "revokedAt": datetime.now(timezone.utc)}
        payload["expiresAt"] = require_datetime(payload.get("expiresAt"), "expiresAt")
        return payload

    def revoke(self, token: str) -> None:
        self.revocations.revoke(self.verify(token)["sessionId"])

    def _sign(self, payload: dict[str, Any]) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        encoded_header = _urlsafe_json(header)
        encoded_payload = _urlsafe_json(payload)
        signature = hmac.new(
            self.signing_secret,
            f"{encoded_header}.{encoded_payload}".encode("ascii"),
            hashlib.sha256,
        )
        return f"{encoded_header}.{encoded_payload}.{_urlsafe_bytes(signature.digest())}"


def _urlsafe_json(payload: dict[str, Any]) -> str:
    return _urlsafe_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _urlsafe_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _pad(value: str) -> bytes:
    return (value + ("=" * (-len(value) % 4))).encode("ascii")
