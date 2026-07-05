from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .validation import require_datetime, require_non_empty_string


class GoogleOAuthExchangeError(Exception):
    def __init__(self, *, error_code: str, status: int | None = None, step: str = "unknown") -> None:
        self.error_code = require_non_empty_string(error_code, "errorCode")
        self.status = status
        self.step = require_non_empty_string(step, "step")
        super().__init__(self.error_code)


class GoogleOAuthHttpTokenExchange:
    def __init__(
        self,
        *,
        client_id: str,
        client_secret_resolver: Any,
        client_secret_ref: str,
        token_endpoint: str = "https://oauth2.googleapis.com/token",
        userinfo_endpoint: str = "https://openidconnect.googleapis.com/v1/userinfo",
        timeout_seconds: int = 10,
        opener: Any = urlopen,
    ) -> None:
        self.client_id = require_non_empty_string(client_id, "clientId")
        self.client_secret_resolver = client_secret_resolver
        self.client_secret_ref = require_non_empty_string(client_secret_ref, "clientSecretRef")
        self.token_endpoint = require_non_empty_string(token_endpoint, "tokenEndpoint")
        self.userinfo_endpoint = require_non_empty_string(userinfo_endpoint, "userinfoEndpoint")
        self.timeout_seconds = timeout_seconds
        self.opener = opener

    def exchange_code(self, *, authorization_code: str, redirect_uri: str) -> dict[str, Any]:
        response = self._post_token(
            {
                "code": require_non_empty_string(authorization_code, "authorizationCode"),
                "client_id": self.client_id,
                "client_secret": self._client_secret(),
                "redirect_uri": require_non_empty_string(redirect_uri, "redirectUri"),
                "grant_type": "authorization_code",
            }
        )
        access_token = require_non_empty_string(response.get("access_token"), "access_token")
        try:
            userinfo = self._get_userinfo(access_token)
        except GoogleOAuthExchangeError:
            raise
        return {
            "googleAccountId": require_non_empty_string(userinfo.get("sub"), "sub"),
            "scopes": str(response.get("scope", "")).split(),
            "accessToken": access_token,
            "refreshToken": response.get("refresh_token"),
            "expiresAt": _expires_at(response),
        }

    def refresh(self, *, refresh_token: str, scopes: list[str]) -> dict[str, Any]:
        try:
            response = self._post_token(
                {
                    "refresh_token": require_non_empty_string(refresh_token, "refreshToken"),
                    "client_id": self.client_id,
                    "client_secret": self._client_secret(),
                    "grant_type": "refresh_token",
                    "scope": " ".join(scopes),
                }
            )
        except GoogleOAuthExchangeError as error:
            if error.error_code in {"invalid_grant", "revoked"}:
                return {"revoked": True, "error": error.error_code}
            raise
        if response.get("error") in {"invalid_grant", "revoked"}:
            return {"revoked": True, "error": response.get("error")}
        return {
            "accessToken": require_non_empty_string(response.get("access_token"), "access_token"),
            "refreshToken": response.get("refresh_token"),
            "expiresAt": _expires_at(response),
        }

    def _client_secret(self) -> str:
        return require_non_empty_string(
            self.client_secret_resolver.resolve(self.client_secret_ref), "clientSecret"
        )

    def _post_token(self, values: dict[str, Any]) -> dict[str, Any]:
        body = urlencode({key: value for key, value in values.items() if value is not None}).encode("utf-8")
        request = Request(
            self.token_endpoint,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        return _read_json(request, self.timeout_seconds, self.opener, step="token")

    def _get_userinfo(self, access_token: str) -> dict[str, Any]:
        request = Request(
            self.userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
            method="GET",
        )
        return _read_json(request, self.timeout_seconds, self.opener, step="userinfo")


def _read_json(request: Request, timeout_seconds: int, opener: Any, *, step: str) -> dict[str, Any]:
    try:
        with opener(request, timeout=timeout_seconds) as response:  # nosec - configured HTTPS endpoints.
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        raise GoogleOAuthExchangeError(
            error_code=_google_error_code(error),
            status=error.code,
            step=step,
        ) from error
    except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as error:
        raise GoogleOAuthExchangeError(error_code="request_failed", step=step) from error
    if not isinstance(payload, dict):
        raise GoogleOAuthExchangeError(error_code="malformed_response", step=step)
    return payload


def _google_error_code(error: HTTPError) -> str:
    try:
        payload = json.loads(error.read().decode("utf-8"))
    except (ValueError, TypeError, json.JSONDecodeError):
        return "http_error"
    if not isinstance(payload, dict):
        return "http_error"
    raw_error = str(payload.get("error") or "").strip()
    return raw_error if raw_error else "http_error"


def _expires_at(response: dict[str, Any]) -> datetime:
    if response.get("expires_at"):
        return require_datetime(response["expires_at"], "expires_at")
    seconds = int(response.get("expires_in") or 3600)
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)
