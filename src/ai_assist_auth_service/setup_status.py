from __future__ import annotations

from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Callable

from .errors import AUTH_ERROR_CODES, AuthError
from .oauth_tokens import OAUTH_PROVIDERS
from .validation import freeze, require_non_empty_string, to_iso


PRODUCT_SESSION_STATUSES = MappingProxyType(
    {
        "ANONYMOUS": "anonymous",
        "AUTHENTICATED": "authenticated",
        "EXPIRED": "expired",
    }
)
GOOGLE_OAUTH_CONNECTION_STATUSES = MappingProxyType(
    {
        "NOT_CONNECTED": "not_connected",
        "CONNECTED": "connected",
        "RECONNECT_REQUIRED": "reconnect_required",
    }
)
SETUP_ERROR_KINDS = MappingProxyType(
    {
        "PRODUCT_SESSION_REQUIRED": "product_session_required",
        "PRODUCT_SESSION_EXPIRED": "product_session_expired",
        "GOOGLE_OAUTH_RECONNECT_REQUIRED": "google_oauth_reconnect_required",
    }
)

_ERROR_CATEGORIES = MappingProxyType(
    {
        "AUTHENTICATION": "AUTHENTICATION",
        "AUTHORIZATION": "AUTHORIZATION",
        "OAUTH": "OAUTH",
    }
)
_STANDARD_ERROR_CODES = MappingProxyType(
    {
        "AUTHENTICATION_REQUIRED": "AUTHENTICATION_REQUIRED",
        "AUTHENTICATION_EXPIRED": "AUTHENTICATION_EXPIRED",
        "MALFORMED_PRODUCT_CREDENTIAL": "MALFORMED_PRODUCT_CREDENTIAL",
        "AUTHORIZATION_DENIED": "AUTHORIZATION_DENIED",
        "OAUTH_RECONNECT_REQUIRED": "OAUTH_RECONNECT_REQUIRED",
    }
)


class AuthSetupStatusService:
    def __init__(
        self,
        *,
        identity_service: Any,
        oauth_token_service: Any,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if identity_service is None or not callable(
            getattr(identity_service, "derive_identity", None)
        ):
            raise TypeError("identityService.deriveIdentity is required.")
        if oauth_token_service is None or not callable(
            getattr(oauth_token_service, "get_google_status", None)
        ):
            raise TypeError("oauthTokenService.getGoogleStatus is required.")
        self.identity_service = identity_service
        self.oauth_token_service = oauth_token_service
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def get_setup_status(
        self,
        *,
        product_session: dict[str, Any] | None = None,
        client_identity: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        errors: list[dict[str, Any]] = []
        try:
            identity = self.identity_service.derive_identity(
                product_session=product_session,
                client_identity=client_identity,
            )
        except AuthError as error:
            product_session_ref, setup_error = _product_session_error_refs(error)
            if setup_error:
                errors.append(setup_error)
            return freeze(
                {
                    "productSession": product_session_ref,
                    "googleOAuth": _google_oauth_not_connected(),
                    "errors": errors,
                    "updatedAt": to_iso(self.clock()),
                }
            )

        try:
            session_id = require_non_empty_string(
                product_session.get("sessionId") if product_session else None,
                "productSession.sessionId",
            )
        except TypeError:
            product_session_ref, setup_error = _product_session_error_refs(
                AuthError(
                    code=AUTH_ERROR_CODES["AUTH_TOKEN_MALFORMED"],
                    message="The product auth token is malformed.",
                    status=401,
                )
            )
            return freeze(
                {
                    "productSession": product_session_ref,
                    "googleOAuth": _google_oauth_not_connected(),
                    "errors": [setup_error],
                    "updatedAt": to_iso(self.clock()),
                }
            )

        google_oauth_ref = _google_oauth_ref(
            self.oauth_token_service.get_google_status(identity=identity)
        )
        if google_oauth_ref["status"] == GOOGLE_OAUTH_CONNECTION_STATUSES["RECONNECT_REQUIRED"]:
            errors.append(
                _setup_error(
                    kind=SETUP_ERROR_KINDS["GOOGLE_OAUTH_RECONNECT_REQUIRED"],
                    error=google_oauth_ref["error"],
                )
            )

        return freeze(
            {
                "productSession": {
                    "status": PRODUCT_SESSION_STATUSES["AUTHENTICATED"],
                    "tenantId": identity["tenantId"],
                    "userId": identity["userId"],
                    "authSubject": identity["authSubject"],
                    "sessionId": session_id,
                    "expiresAt": identity["expiresAt"],
                },
                "googleOAuth": google_oauth_ref,
                "errors": errors,
                "updatedAt": to_iso(self.clock()),
            }
        )


def _product_session_error_refs(error: AuthError) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if error.code == AUTH_ERROR_CODES["AUTH_TOKEN_EXPIRED"]:
        contract_error = _contract_error(
            code=_STANDARD_ERROR_CODES["AUTHENTICATION_EXPIRED"],
            category=_ERROR_CATEGORIES["AUTHENTICATION"],
            message="Product session expired.",
            http_status=401,
            target="authorization",
        )
        return (
            {
                "status": PRODUCT_SESSION_STATUSES["EXPIRED"],
                "error": contract_error,
            },
            _setup_error(
                kind=SETUP_ERROR_KINDS["PRODUCT_SESSION_EXPIRED"],
                error=contract_error,
            ),
        )

    contract_error = _product_session_contract_error(error)
    return (
        {
            "status": PRODUCT_SESSION_STATUSES["ANONYMOUS"],
            "error": contract_error,
        },
        _setup_error(
            kind=SETUP_ERROR_KINDS["PRODUCT_SESSION_REQUIRED"],
            error=contract_error,
        ),
    )


def _product_session_contract_error(error: AuthError) -> dict[str, Any]:
    if error.code == AUTH_ERROR_CODES["AUTH_TOKEN_MALFORMED"]:
        return _contract_error(
            code=_STANDARD_ERROR_CODES["MALFORMED_PRODUCT_CREDENTIAL"],
            category=_ERROR_CATEGORIES["AUTHENTICATION"],
            message="Product session is malformed.",
            http_status=400,
            target="authorization",
        )
    if error.status == 403:
        return _contract_error(
            code=_STANDARD_ERROR_CODES["AUTHORIZATION_DENIED"],
            category=_ERROR_CATEGORIES["AUTHORIZATION"],
            message="Product session is not authorized for this tenant.",
            http_status=403,
            target="authorization",
        )
    return _contract_error(
        code=_STANDARD_ERROR_CODES["AUTHENTICATION_REQUIRED"],
        category=_ERROR_CATEGORIES["AUTHENTICATION"],
        message="Product session is required.",
        http_status=401,
        target="authorization",
    )


def _google_oauth_ref(status: dict[str, Any]) -> dict[str, Any]:
    accounts = list(status["accounts"])
    if len(accounts) == 0:
        return _google_oauth_not_connected()

    available = [account for account in accounts if account["isAvailable"]]
    if available:
        account = sorted(available, key=lambda item: item["updatedAt"], reverse=True)[0]
        return {
            "provider": OAUTH_PROVIDERS["GOOGLE"],
            "status": GOOGLE_OAUTH_CONNECTION_STATUSES["CONNECTED"],
            "googleAccountId": account["googleAccountId"],
            "scopes": list(account["scopes"]),
            "connectedAt": account["updatedAt"],
            "expiresAt": account["expiresAt"],
        }

    reconnect_account = sorted(accounts, key=lambda item: item["updatedAt"], reverse=True)[0]
    return {
        "provider": OAUTH_PROVIDERS["GOOGLE"],
        "status": GOOGLE_OAUTH_CONNECTION_STATUSES["RECONNECT_REQUIRED"],
        "googleAccountId": reconnect_account["googleAccountId"],
        "error": _contract_error(
            code=_STANDARD_ERROR_CODES["OAUTH_RECONNECT_REQUIRED"],
            category=_ERROR_CATEGORIES["OAUTH"],
            message="Google connection must be refreshed.",
            http_status=401,
            target="googleOAuth",
        ),
    }


def _google_oauth_not_connected() -> dict[str, Any]:
    return {
        "provider": OAUTH_PROVIDERS["GOOGLE"],
        "status": GOOGLE_OAUTH_CONNECTION_STATUSES["NOT_CONNECTED"],
    }


def _setup_error(*, kind: str, error: dict[str, Any]) -> dict[str, Any]:
    return {"kind": kind, "error": error}


def _contract_error(
    *,
    code: str,
    category: str,
    message: str,
    http_status: int,
    target: str,
) -> dict[str, Any]:
    return {
        "code": code,
        "category": category,
        "message": message,
        "retryable": False,
        "httpStatus": http_status,
        "target": target,
    }
