from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Callable
from urllib.parse import urlencode

from .errors import AUTH_ERROR_CODES, AuthError, validation_failed
from .identity import require_identity
from .oauth_tokens import OAUTH_PROVIDERS, OAuthTokenService
from .validation import clone_datetime, freeze, require_datetime, require_non_empty_string, to_iso


GOOGLE_OAUTH_SCOPES = (
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/drive.metadata.readonly",
)

OAUTH_AUDIT_EVENTS = MappingProxyType(
    {
        "STARTED": "google_oauth_started",
        "CONNECTED": "google_oauth_connected",
        "DENIED": "google_oauth_denied",
    }
)

_STATE_TTL = timedelta(minutes=10)
_STATE_VERSION = 1


class InMemoryOAuthStateRepository:
    def __init__(self) -> None:
        self.records: dict[str, dict[str, Any]] = {}

    def put(self, record: dict[str, Any]) -> dict[str, Any]:
        self.records[record["nonce"]] = _clone_state_record(record)
        return _clone_state_record(record)

    def consume(self, nonce: str) -> dict[str, Any] | None:
        record = self.records.pop(nonce, None)
        return _clone_state_record(record) if record else None


class SignedOAuthStateCodec:
    def __init__(self, *, signing_secret: str) -> None:
        require_non_empty_string(signing_secret, "signingSecret")
        self.signing_secret = signing_secret.encode("utf-8")

    def sign(self, payload: dict[str, Any]) -> str:
        encoded_payload = _urlsafe_json(payload)
        signature = hmac.new(self.signing_secret, encoded_payload.encode("ascii"), hashlib.sha256)
        return f"{encoded_payload}.{_urlsafe_bytes(signature.digest())}"

    def verify(self, state: str) -> dict[str, Any]:
        try:
            encoded_payload, encoded_signature = state.split(".", 1)
        except ValueError:
            raise _invalid_state("OAuth state is malformed.")
        expected = hmac.new(self.signing_secret, encoded_payload.encode("ascii"), hashlib.sha256)
        if not hmac.compare_digest(_urlsafe_bytes(expected.digest()), encoded_signature):
            raise _invalid_state("OAuth state signature is invalid.")
        try:
            decoded = base64.urlsafe_b64decode(_pad_base64(encoded_payload)).decode("utf-8")
            payload = json.loads(decoded)
        except (ValueError, TypeError, json.JSONDecodeError):
            raise _invalid_state("OAuth state payload is invalid.")
        if not isinstance(payload, dict):
            raise _invalid_state("OAuth state payload is invalid.")
        return payload


class GoogleOAuthFlowService:
    def __init__(
        self,
        *,
        oauth_token_service: OAuthTokenService,
        state_repository: InMemoryOAuthStateRepository,
        state_codec: SignedOAuthStateCodec,
        token_exchange: Any,
        client_id: str,
        redirect_uri: str,
        allowed_redirect_targets: list[str] | tuple[str, ...],
        nonce_factory: Callable[[], str],
        authorization_endpoint: str = "https://accounts.google.com/o/oauth2/v2/auth",
        clock: Callable[[], datetime] | None = None,
        audit_sink: Any | None = None,
    ) -> None:
        if oauth_token_service is None:
            raise TypeError("oauthTokenService is required.")
        if state_repository is None:
            raise TypeError("stateRepository is required.")
        if state_codec is None:
            raise TypeError("stateCodec is required.")
        if token_exchange is None or not callable(getattr(token_exchange, "exchange_code", None)):
            raise TypeError("tokenExchange.exchange_code is required.")
        self.oauth_token_service = oauth_token_service
        self.state_repository = state_repository
        self.state_codec = state_codec
        self.token_exchange = token_exchange
        self.client_id = require_non_empty_string(client_id, "clientId")
        self.redirect_uri = require_non_empty_string(redirect_uri, "redirectUri")
        self.allowed_redirect_targets = tuple(
            require_non_empty_string(target, "allowedRedirectTarget")
            for target in allowed_redirect_targets
        )
        if len(self.allowed_redirect_targets) == 0:
            raise TypeError("allowedRedirectTargets must not be empty.")
        self.nonce_factory = nonce_factory
        self.authorization_endpoint = require_non_empty_string(
            authorization_endpoint, "authorizationEndpoint"
        )
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.audit_sink = audit_sink

    def start_google_oauth(
        self,
        *,
        identity: dict[str, Any],
        redirect_target: str,
        scopes: list[str] | tuple[str, ...] = GOOGLE_OAUTH_SCOPES,
    ) -> dict[str, Any]:
        require_identity(identity)
        redirect_target = self._validated_redirect_target(redirect_target)
        normalized_scopes = _normalize_scopes(scopes)
        nonce = require_non_empty_string(self.nonce_factory(), "nonce")
        now = self.clock()
        expires_at = now + _STATE_TTL
        payload = {
            "version": _STATE_VERSION,
            "nonce": nonce,
            "tenantId": identity["tenantId"],
            "userId": identity["userId"],
            "authSubject": identity["authSubject"],
            "redirectTarget": redirect_target,
            "expiresAt": to_iso(expires_at),
        }
        state = self.state_codec.sign(payload)
        self.state_repository.put({**payload, "stateHash": _state_hash(state), "createdAt": now})
        self._audit(
            OAUTH_AUDIT_EVENTS["STARTED"],
            identity=identity,
            status="started",
            google_account_id=None,
        )
        query = urlencode(
            {
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "response_type": "code",
                "scope": " ".join(normalized_scopes),
                "access_type": "offline",
                "prompt": "consent",
                "state": state,
            }
        )
        return freeze({
            "provider": OAUTH_PROVIDERS["GOOGLE"],
            "authorizationUrl": f"{self.authorization_endpoint}?{query}",
            "state": state,
            "expiresAt": to_iso(expires_at),
            "scopes": normalized_scopes,
            "redirectTarget": redirect_target,
        })

    def complete_google_oauth(
        self,
        *,
        identity: dict[str, Any],
        state: str,
        authorization_code: str,
    ) -> dict[str, Any]:
        require_identity(identity)
        require_non_empty_string(authorization_code, "authorizationCode")
        payload = self.state_codec.verify(require_non_empty_string(state, "state"))
        nonce = require_non_empty_string(payload.get("nonce"), "state.nonce")
        record = self.state_repository.consume(nonce)
        if record is None or record["stateHash"] != _state_hash(state):
            self._audit(OAUTH_AUDIT_EVENTS["DENIED"], identity=identity, status="state_replay")
            raise _invalid_state("OAuth state has already been used or is unavailable.")
        expires_at = require_datetime(record["expiresAt"], "state.expiresAt")
        if expires_at <= self.clock():
            self._audit(OAUTH_AUDIT_EVENTS["DENIED"], identity=identity, status="state_expired")
            raise _invalid_state("OAuth state has expired.")
        if record["tenantId"] != identity["tenantId"] or record["userId"] != identity["userId"]:
            self._audit(OAUTH_AUDIT_EVENTS["DENIED"], identity=identity, status="identity_mismatch")
            raise _invalid_state("OAuth state does not match the authenticated user.")

        try:
            token_response = self.token_exchange.exchange_code(
                authorization_code=authorization_code,
                redirect_uri=self.redirect_uri,
            )
        except Exception:
            self._audit(OAUTH_AUDIT_EVENTS["DENIED"], identity=identity, status="exchange_failed")
            raise AuthError(
                code=AUTH_ERROR_CODES["OAUTH_EXCHANGE_FAILED"],
                message="Google OAuth code exchange failed.",
                status=502,
            )

        try:
            metadata = self.oauth_token_service.connect_google(
                identity=identity,
                google_account_id=require_non_empty_string(
                    token_response.get("googleAccountId"), "googleAccountId"
                ),
                scopes=list(_normalize_scopes(token_response.get("scopes") or GOOGLE_OAUTH_SCOPES)),
                access_token=require_non_empty_string(token_response.get("accessToken"), "accessToken"),
                refresh_token=token_response.get("refreshToken"),
                expires_at=require_datetime(token_response.get("expiresAt"), "expiresAt"),
            )
        except (TypeError, ValueError):
            self._audit(OAUTH_AUDIT_EVENTS["DENIED"], identity=identity, status="exchange_failed")
            raise AuthError(
                code=AUTH_ERROR_CODES["OAUTH_EXCHANGE_FAILED"],
                message="Google OAuth code exchange failed.",
                status=502,
            )
        self._audit(
            OAUTH_AUDIT_EVENTS["CONNECTED"],
            identity=identity,
            status="connected",
            google_account_id=metadata["googleAccountId"],
        )
        return freeze({
            "provider": OAUTH_PROVIDERS["GOOGLE"],
            "status": "connected",
            "googleAccountId": metadata["googleAccountId"],
            "scopes": metadata["scopes"],
            "expiresAt": metadata["expiresAt"],
            "redirectTarget": record["redirectTarget"],
        })

    def _validated_redirect_target(self, redirect_target: str) -> str:
        target = require_non_empty_string(redirect_target, "redirectTarget")
        if _normalize_redirect_target(target) not in {
            _normalize_redirect_target(allowed) for allowed in self.allowed_redirect_targets
        }:
            raise validation_failed("redirectTarget", "OAuth redirect target is not allowed.")
        return target

    def _audit(
        self,
        event_name: str,
        *,
        identity: dict[str, Any],
        status: str,
        google_account_id: str | None = None,
    ) -> None:
        if self.audit_sink is None:
            return
        self.audit_sink.emit(
            {
                "event": event_name,
                "tenantId": identity["tenantId"],
                "userId": identity["userId"],
                "provider": OAUTH_PROVIDERS["GOOGLE"],
                "status": status,
                "googleAccountId": google_account_id,
            }
        )


def _normalize_scopes(scopes: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    normalized = tuple(sorted({str(scope).strip() for scope in scopes if str(scope).strip()}))
    if len(normalized) == 0:
        raise validation_failed("scopes", "At least one OAuth scope is required.")
    return normalized


def _normalize_redirect_target(value: str) -> str:
    return require_non_empty_string(value, "redirectTarget").rstrip("/")


def _urlsafe_json(payload: dict[str, Any]) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _urlsafe_bytes(body)


def _urlsafe_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _pad_base64(value: str) -> bytes:
    return (value + ("=" * (-len(value) % 4))).encode("ascii")


def _state_hash(state: str) -> str:
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


def _invalid_state(message: str) -> AuthError:
    return AuthError(code=AUTH_ERROR_CODES["OAUTH_STATE_INVALID"], message=message, status=400)


def _clone_state_record(record: dict[str, Any] | None) -> dict[str, Any] | None:
    if record is None:
        return None
    return {
        **record,
        "createdAt": clone_datetime(record["createdAt"]),
    }
