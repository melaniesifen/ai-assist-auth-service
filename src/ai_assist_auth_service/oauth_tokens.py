from __future__ import annotations

from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Callable

from .errors import AUTH_ERROR_CODES, AuthError, forbidden, validation_failed
from .identity import require_identity
from .validation import freeze, clone_datetime, require_datetime, require_non_empty_string, to_iso


OAUTH_PROVIDERS = MappingProxyType({"GOOGLE": "google"})
OAUTH_TOKEN_STATUS = MappingProxyType({"ACTIVE": "active", "REVOKED": "revoked"})
GOOGLE_TOKEN_HANDOFF_OPERATIONS = MappingProxyType(
    {
        "LIST_RESOURCES": "listResources",
        "READ_CONTEXT": "readContext",
        "APPLY_ACTION": "applyAction",
    }
)

_OAUTH_TOKEN_PURPOSE = "oauth-token"
_GOOGLE_OAUTH_RECONNECT_REQUIRED = "OAUTH_RECONNECT_REQUIRED"


class InMemoryOAuthTokenRepository:
    def __init__(self) -> None:
        self.records: dict[str, dict[str, Any]] = {}

    def upsert(self, record: dict[str, Any]) -> dict[str, Any]:
        self.records[_token_key(record)] = _clone_record(record)
        return _clone_record(record)

    def get(
        self,
        *,
        tenant_id: str,
        user_id: str,
        provider: str,
        google_account_id: str,
    ) -> dict[str, Any] | None:
        record = self.records.get(
            _token_key(
                {
                    "tenantId": tenant_id,
                    "userId": user_id,
                    "provider": provider,
                    "googleAccountId": google_account_id,
                }
            )
        )
        return _clone_record(record) if record else None

    def list_for_user(
        self,
        *,
        tenant_id: str,
        user_id: str,
        provider: str | None = None,
    ) -> list[dict[str, Any]]:
        return [
            _clone_record(record)
            for record in self.records.values()
            if record["tenantId"] == tenant_id
            and record["userId"] == user_id
            and (provider is None or record["provider"] == provider)
        ]


class OAuthTokenService:
    def __init__(
        self,
        *,
        tenant_directory: Any,
        token_repository: InMemoryOAuthTokenRepository,
        token_protector: Any,
        token_exchange: Any | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if tenant_directory is None:
            raise TypeError("tenantDirectory is required.")
        if token_repository is None:
            raise TypeError("tokenRepository is required.")
        if token_protector is None or not callable(getattr(token_protector, "encrypt", None)):
            raise TypeError("tokenProtector.encrypt is required.")
        self.tenant_directory = tenant_directory
        self.token_repository = token_repository
        self.token_protector = token_protector
        self.token_exchange = token_exchange
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def connect_google(
        self,
        *,
        identity: dict[str, Any],
        google_account_id: str,
        scopes: list[Any],
        access_token: str,
        refresh_token: str | None = None,
        expires_at: datetime,
    ) -> dict[str, Any]:
        require_identity(identity)
        self.tenant_directory.assert_active_membership(
            tenant_id=identity["tenantId"], user_id=identity["userId"]
        )
        try:
            require_non_empty_string(google_account_id, "googleAccountId")
        except TypeError:
            raise validation_failed("googleAccountId", "Google account ID is required.")
        try:
            require_non_empty_string(access_token, "accessToken")
        except TypeError:
            raise validation_failed("accessToken", "Google OAuth access token is required.")
        normalized_scopes = _normalize_scopes(scopes)
        now = self.clock()
        try:
            token_expires_at = require_datetime(expires_at, "expiresAt")
        except (TypeError, ValueError):
            raise validation_failed("expiresAt", "Google OAuth token expiry must be a valid datetime.")
        context = _encryption_context(identity, OAUTH_PROVIDERS["GOOGLE"])
        existing = self.token_repository.get(
            tenant_id=identity["tenantId"],
            user_id=identity["userId"],
            provider=OAUTH_PROVIDERS["GOOGLE"],
            google_account_id=google_account_id,
        )

        record = {
            "tenantId": identity["tenantId"],
            "userId": identity["userId"],
            "provider": OAUTH_PROVIDERS["GOOGLE"],
            "googleAccountId": google_account_id,
            "scopes": normalized_scopes,
            "accessTokenCiphertext": self.token_protector.encrypt(access_token, context=context),
            "refreshTokenCiphertext": (
                self.token_protector.encrypt(refresh_token, context=context)
                if refresh_token
                else existing.get("refreshTokenCiphertext")
                if existing
                else None
            ),
            "expiresAt": clone_datetime(token_expires_at),
            "createdAt": existing["createdAt"] if existing else now,
            "updatedAt": now,
            "revokedAt": None,
            "status": OAUTH_TOKEN_STATUS["ACTIVE"],
        }
        return _token_metadata(self.token_repository.upsert(record), now)

    def get_google_status(
        self,
        *,
        identity: dict[str, Any],
        google_account_id: str | None = None,
    ) -> dict[str, Any]:
        require_identity(identity)
        self.tenant_directory.assert_active_membership(
            tenant_id=identity["tenantId"], user_id=identity["userId"]
        )
        if google_account_id:
            record = self.token_repository.get(
                tenant_id=identity["tenantId"],
                user_id=identity["userId"],
                provider=OAUTH_PROVIDERS["GOOGLE"],
                google_account_id=google_account_id,
            )
            records = [record] if record else []
        else:
            records = self.token_repository.list_for_user(
                tenant_id=identity["tenantId"],
                user_id=identity["userId"],
                provider=OAUTH_PROVIDERS["GOOGLE"],
            )

        now = self.clock()
        accounts = [_token_metadata(record, now) for record in records]
        return freeze({
            "tenantId": identity["tenantId"],
            "userId": identity["userId"],
            "provider": OAUTH_PROVIDERS["GOOGLE"],
            "connected": any(_is_google_token_available(record, now) for record in records),
            "accounts": accounts,
        })

    def assert_google_token_usable(
        self,
        *,
        identity: dict[str, Any],
        google_account_id: str,
    ) -> dict[str, Any]:
        require_identity(identity)
        self.tenant_directory.assert_active_membership(
            tenant_id=identity["tenantId"], user_id=identity["userId"]
        )
        record = self.token_repository.get(
            tenant_id=identity["tenantId"],
            user_id=identity["userId"],
            provider=OAUTH_PROVIDERS["GOOGLE"],
            google_account_id=google_account_id,
        )
        if record is None:
            raise AuthError(
                code=AUTH_ERROR_CODES["OAUTH_TOKEN_NOT_FOUND"],
                message="Google OAuth connection is not available.",
                status=403,
            )
        now = self.clock()
        if record["status"] != OAUTH_TOKEN_STATUS["ACTIVE"] or record["revokedAt"]:
            raise AuthError(
                code=AUTH_ERROR_CODES["OAUTH_TOKEN_REVOKED"],
                message="Google OAuth connection must be reconnected.",
                status=403,
            )
        if not _is_google_token_available(record, now):
            raise AuthError(
                code=AUTH_ERROR_CODES["OAUTH_TOKEN_REVOKED"],
                message="Google OAuth connection has expired and cannot be refreshed.",
                status=403,
            )
        return _token_metadata(record, now)

    def get_google_access_token(
        self,
        *,
        identity: dict[str, Any],
        google_account_id: str,
        operation: str,
        required_scopes: list[Any] | tuple[Any, ...],
    ) -> dict[str, Any]:
        if operation == GOOGLE_TOKEN_HANDOFF_OPERATIONS["APPLY_ACTION"]:
            raise validation_failed(
                "operation",
                "Apply validation must use metadata-only Google token handoff status.",
            )
        status = self.get_google_token_handoff_status(
            identity=identity,
            google_account_id=google_account_id,
            operation=operation,
            required_scopes=required_scopes,
        )
        if status["reconnectRequired"]:
            return status

        record = self.token_repository.get(
            tenant_id=identity["tenantId"],
            user_id=identity["userId"],
            provider=OAUTH_PROVIDERS["GOOGLE"],
            google_account_id=google_account_id,
        )

        if record["expiresAt"] <= self.clock() and record["refreshTokenCiphertext"]:
            record = self.refresh_google_access_token(
                identity=identity,
                google_account_id=google_account_id,
            )
            if record["status"] != OAUTH_TOKEN_STATUS["ACTIVE"] or record["revokedAt"]:
                return _reconnect_required_handoff(
                    identity=identity,
                    google_account_id=google_account_id,
                    operation=operation,
                    required_scopes=list(status["requiredScopes"]),
                    scopes=list(record["scopes"]),
                    expires_at=record["expiresAt"],
                    reason="revoked",
                    message="Google OAuth connection must be reconnected.",
                )

        decrypt = getattr(self.token_protector, "decrypt", None)
        if not callable(decrypt):
            raise AuthError(
                code=AUTH_ERROR_CODES["OAUTH_TOKEN_REVOKED"],
                message="Google OAuth access token is unavailable.",
                status=403,
            )
        access_token = decrypt(
            record["accessTokenCiphertext"],
            context=_encryption_context(identity, OAUTH_PROVIDERS["GOOGLE"]),
        )
        if not isinstance(access_token, str) or len(access_token.strip()) == 0:
            return _reconnect_required_handoff(
                identity=identity,
                google_account_id=google_account_id,
                operation=operation,
                required_scopes=list(status["requiredScopes"]),
                scopes=list(record["scopes"]),
                expires_at=record["expiresAt"],
                reason="unavailable",
                message="Google OAuth access token is unavailable.",
            )

        return freeze({**status, "accessToken": access_token})

    def get_google_token_handoff_status(
        self,
        *,
        identity: dict[str, Any],
        google_account_id: str,
        operation: str,
        required_scopes: list[Any] | tuple[Any, ...],
    ) -> dict[str, Any]:
        require_identity(identity)
        self.tenant_directory.assert_active_membership(
            tenant_id=identity["tenantId"], user_id=identity["userId"]
        )
        try:
            require_non_empty_string(google_account_id, "googleAccountId")
        except TypeError:
            raise validation_failed("googleAccountId", "Google account ID is required.")
        if operation not in set(GOOGLE_TOKEN_HANDOFF_OPERATIONS.values()):
            raise validation_failed("operation", "Google token handoff operation is not supported.")
        normalized_required_scopes = _normalize_scopes(list(required_scopes))
        record = self.token_repository.get(
            tenant_id=identity["tenantId"],
            user_id=identity["userId"],
            provider=OAUTH_PROVIDERS["GOOGLE"],
            google_account_id=google_account_id,
        )
        now = self.clock()
        if record is None:
            return _reconnect_required_handoff(
                identity=identity,
                google_account_id=google_account_id,
                operation=operation,
                required_scopes=normalized_required_scopes,
                reason="unavailable",
                message="Google OAuth connection is not available.",
            )

        metadata = _token_metadata(record, now)
        if record["status"] != OAUTH_TOKEN_STATUS["ACTIVE"] or record["revokedAt"]:
            return _reconnect_required_handoff(
                identity=identity,
                google_account_id=google_account_id,
                operation=operation,
                required_scopes=normalized_required_scopes,
                scopes=list(record["scopes"]),
                expires_at=record["expiresAt"],
                reason="revoked",
                message="Google OAuth connection must be reconnected.",
            )
        if metadata["isExpired"]:
            if record["refreshTokenCiphertext"]:
                return freeze({
                    "provider": OAUTH_PROVIDERS["GOOGLE"],
                    "googleAccountId": record["googleAccountId"],
                    "tenantId": identity["tenantId"],
                    "userId": identity["userId"],
                    "operation": operation,
                    "status": OAUTH_TOKEN_STATUS["ACTIVE"],
                    "scopes": list(record["scopes"]),
                    "requiredScopes": normalized_required_scopes,
                    "expiresAt": to_iso(record["expiresAt"]),
                    "refreshRequired": True,
                    "reconnectRequired": False,
                })
            return _reconnect_required_handoff(
                identity=identity,
                google_account_id=google_account_id,
                operation=operation,
                required_scopes=normalized_required_scopes,
                scopes=list(record["scopes"]),
                expires_at=record["expiresAt"],
                reason="expired",
                message="Google OAuth connection has expired.",
            )

        missing_scopes = [scope for scope in normalized_required_scopes if scope not in record["scopes"]]
        if missing_scopes:
            return _reconnect_required_handoff(
                identity=identity,
                google_account_id=google_account_id,
                operation=operation,
                required_scopes=normalized_required_scopes,
                scopes=list(record["scopes"]),
                expires_at=record["expiresAt"],
                reason="insufficient_scope",
                message="Google OAuth connection does not include required scopes.",
                details={"missingScopes": missing_scopes},
            )

        return freeze({
            "provider": OAUTH_PROVIDERS["GOOGLE"],
            "googleAccountId": record["googleAccountId"],
            "tenantId": identity["tenantId"],
            "userId": identity["userId"],
            "operation": operation,
            "status": OAUTH_TOKEN_STATUS["ACTIVE"],
            "scopes": list(record["scopes"]),
            "requiredScopes": normalized_required_scopes,
            "expiresAt": to_iso(record["expiresAt"]),
            "refreshRequired": False,
            "reconnectRequired": False,
        })

    def refresh_google_access_token(
        self,
        *,
        identity: dict[str, Any],
        google_account_id: str,
    ) -> dict[str, Any]:
        require_identity(identity)
        self.tenant_directory.assert_active_membership(
            tenant_id=identity["tenantId"], user_id=identity["userId"]
        )
        record = self.token_repository.get(
            tenant_id=identity["tenantId"],
            user_id=identity["userId"],
            provider=OAUTH_PROVIDERS["GOOGLE"],
            google_account_id=google_account_id,
        )
        if record is None:
            raise AuthError(
                code=AUTH_ERROR_CODES["OAUTH_TOKEN_NOT_FOUND"],
                message="Google OAuth connection is not available.",
                status=403,
            )
        if record["status"] != OAUTH_TOKEN_STATUS["ACTIVE"] or record["revokedAt"]:
            raise AuthError(
                code=AUTH_ERROR_CODES["OAUTH_TOKEN_REVOKED"],
                message="Google OAuth connection must be reconnected.",
                status=403,
            )
        if not record["refreshTokenCiphertext"]:
            raise AuthError(
                code=AUTH_ERROR_CODES["OAUTH_TOKEN_REVOKED"],
                message="Google OAuth connection has expired and cannot be refreshed.",
                status=403,
            )
        if self.token_exchange is None or not callable(getattr(self.token_exchange, "refresh", None)):
            raise AuthError(
                code=AUTH_ERROR_CODES["OAUTH_REFRESH_FAILED"],
                message="Google OAuth refresh is not configured.",
                status=503,
            )

        context = _encryption_context(identity, OAUTH_PROVIDERS["GOOGLE"])
        try:
            refresh_token = self.token_protector.decrypt(
                record["refreshTokenCiphertext"],
                context=context,
            )
            refreshed = self.token_exchange.refresh(refresh_token=refresh_token, scopes=list(record["scopes"]))
        except Exception:
            return self._mark_google_reconnect_required(record, reason="refresh_failed")

        if refreshed.get("revoked") or refreshed.get("error") in {"invalid_grant", "revoked"}:
            return self._mark_google_reconnect_required(record, reason="revoked")

        try:
            access_token = require_non_empty_string(refreshed.get("accessToken"), "accessToken")
            expires_at = require_datetime(refreshed.get("expiresAt"), "expiresAt")
        except (TypeError, ValueError):
            return self._mark_google_reconnect_required(record, reason="refresh_failed")

        now = self.clock()
        record["accessTokenCiphertext"] = self.token_protector.encrypt(access_token, context=context)
        if refreshed.get("refreshToken"):
            record["refreshTokenCiphertext"] = self.token_protector.encrypt(
                refreshed["refreshToken"], context=context
            )
        record["expiresAt"] = clone_datetime(expires_at)
        record["updatedAt"] = now
        record["status"] = OAUTH_TOKEN_STATUS["ACTIVE"]
        record["revokedAt"] = None
        return self.token_repository.upsert(record)

    def revoke_google(
        self,
        *,
        identity: dict[str, Any],
        google_account_id: str,
        revoked_at: datetime | None = None,
    ) -> dict[str, Any]:
        require_identity(identity)
        self.tenant_directory.assert_active_membership(
            tenant_id=identity["tenantId"], user_id=identity["userId"]
        )
        record = self.token_repository.get(
            tenant_id=identity["tenantId"],
            user_id=identity["userId"],
            provider=OAUTH_PROVIDERS["GOOGLE"],
            google_account_id=google_account_id,
        )
        if record is None:
            raise forbidden()
        effective_revoked_at = clone_datetime(revoked_at or self.clock())
        record["status"] = OAUTH_TOKEN_STATUS["REVOKED"]
        record["revokedAt"] = effective_revoked_at
        record["updatedAt"] = effective_revoked_at
        record["accessTokenCiphertext"] = None
        record["refreshTokenCiphertext"] = None
        return _token_metadata(self.token_repository.upsert(record), self.clock())

    def disconnect_google(
        self,
        *,
        identity: dict[str, Any],
        google_account_id: str,
    ) -> dict[str, Any]:
        return self.revoke_google(identity=identity, google_account_id=google_account_id)

    def _mark_google_reconnect_required(self, record: dict[str, Any], *, reason: str) -> dict[str, Any]:
        now = self.clock()
        record["status"] = OAUTH_TOKEN_STATUS["REVOKED"]
        record["revokedAt"] = now
        record["updatedAt"] = now
        record["accessTokenCiphertext"] = None
        record["refreshTokenCiphertext"] = None
        return self.token_repository.upsert(record)


def _normalize_scopes(scopes: list[Any]) -> list[str]:
    if not isinstance(scopes, list) or len(scopes) == 0:
        raise validation_failed("scopes", "At least one OAuth scope is required.")
    normalized = sorted({str(scope).strip() for scope in scopes if str(scope).strip()})
    if len(normalized) == 0:
        raise validation_failed("scopes", "At least one OAuth scope is required.")
    return normalized


def _encryption_context(identity: dict[str, Any], provider: str) -> dict[str, str]:
    return {
        "tenantId": identity["tenantId"],
        "userId": identity["userId"],
        "provider": provider,
        "purpose": _OAUTH_TOKEN_PURPOSE,
    }


def _token_metadata(record: dict[str, Any], now: datetime) -> dict[str, Any]:
    is_expired = record["expiresAt"] <= now
    refresh_available = bool(record["refreshTokenCiphertext"])
    is_available = _is_google_token_available(record, now)
    return freeze({
        "tenantId": record["tenantId"],
        "userId": record["userId"],
        "provider": record["provider"],
        "googleAccountId": record["googleAccountId"],
        "scopes": list(record["scopes"]),
        "status": record["status"],
        "isExpired": is_expired,
        "isAvailable": is_available,
        "refreshRequired": (
            is_expired and refresh_available and record["status"] == OAUTH_TOKEN_STATUS["ACTIVE"]
        ),
        "reconnectRequired": not is_available,
        "expiresAt": to_iso(record["expiresAt"]),
        "createdAt": to_iso(record["createdAt"]),
        "updatedAt": to_iso(record["updatedAt"]),
        "revokedAt": to_iso(record["revokedAt"]),
    })


def _reconnect_required_handoff(
    *,
    identity: dict[str, Any],
    google_account_id: str,
    operation: str,
    required_scopes: list[str],
    reason: str,
    message: str,
    scopes: list[str] | None = None,
    expires_at: datetime | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return freeze({
        "provider": OAUTH_PROVIDERS["GOOGLE"],
        "googleAccountId": google_account_id,
        "tenantId": identity["tenantId"],
        "userId": identity["userId"],
        "operation": operation,
        "status": "reconnect_required",
        "scopes": scopes or [],
        "requiredScopes": required_scopes,
        "expiresAt": to_iso(expires_at),
        "refreshRequired": False,
        "reconnectRequired": True,
        "error": {
            "code": _GOOGLE_OAUTH_RECONNECT_REQUIRED,
            "category": "OAUTH",
            "message": message,
            "retryable": False,
            "httpStatus": 401,
            "target": "googleOAuth",
            "reason": reason,
            "details": details or {},
        },
    })


def _is_google_token_available(record: dict[str, Any], now: datetime) -> bool:
    return (
        record["status"] == OAUTH_TOKEN_STATUS["ACTIVE"]
        and not record["revokedAt"]
        and (record["expiresAt"] > now or bool(record["refreshTokenCiphertext"]))
    )


def _token_key(record: dict[str, Any]) -> str:
    return (
        f"{record['tenantId']}:{record['userId']}:{record['provider']}:"
        f"{record['googleAccountId']}"
    )


def _clone_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        **record,
        "scopes": list(record["scopes"]),
        "expiresAt": clone_datetime(record["expiresAt"]),
        "createdAt": clone_datetime(record["createdAt"]),
        "updatedAt": clone_datetime(record["updatedAt"]),
        "revokedAt": clone_datetime(record["revokedAt"]),
    }
