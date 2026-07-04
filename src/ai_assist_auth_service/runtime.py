from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import urlparse

from .errors import validation_failed
from .identity import AUTH_REFERENCE_TYPES
from .validation import freeze, require_non_empty_string


AUTH_RUNTIME_CONFIG_KEYS = MappingProxyType(
    {
        "APP_ENV": "APP_ENV",
        "AWS_REGION": "AWS_REGION",
        "TRUSTED_USER_MODE": "TRUSTED_USER_MODE",
        "ALLOWED_ORIGINS": "ALLOWED_ORIGINS",
        "WEB_APP_BASE_URL": "WEB_APP_BASE_URL",
        "API_BASE_URL": "API_BASE_URL",
        "SSE_BASE_URL": "SSE_BASE_URL",
        "GOOGLE_OAUTH_CLIENT_ID": "GOOGLE_OAUTH_CLIENT_ID",
        "GOOGLE_OAUTH_CLIENT_SECRET_REF": "GOOGLE_OAUTH_CLIENT_SECRET_REF",
        "GOOGLE_OAUTH_CALLBACK_URL": "GOOGLE_OAUTH_CALLBACK_URL",
        "APP_KMS_KEY_ID": "APP_KMS_KEY_ID",
        "OAUTH_TOKEN_TABLE_NAME": "OAUTH_TOKEN_TABLE_NAME",
    }
)

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class AuthRuntimeConfig:
    def __init__(
        self,
        *,
        app_env: str,
        aws_region: str,
        trusted_user_mode: bool,
        allowed_origins: list[str] | tuple[str, ...],
        web_app_base_url: str,
        api_base_url: str,
        sse_base_url: str,
        google_oauth_client_id: str,
        google_oauth_callback_url: str,
        google_oauth_client_secret_ref: str,
        app_kms_key_id: str,
        oauth_token_table_name: str,
    ) -> None:
        self.app_env = require_non_empty_string(app_env, "APP_ENV")
        self.aws_region = require_non_empty_string(aws_region, "AWS_REGION")
        self.trusted_user_mode = _coerce_bool(trusted_user_mode)
        if not isinstance(allowed_origins, (list, tuple)):
            raise validation_failed("ALLOWED_ORIGINS", "Allowed origins must be a list or tuple.")
        self.allowed_origins = tuple(
            _validate_url(origin, field="ALLOWED_ORIGINS", allow_local_http=True)
            for origin in allowed_origins
            if str(origin).strip()
        )
        if not self.allowed_origins:
            raise validation_failed("ALLOWED_ORIGINS", "At least one allowed origin is required.")
        self.web_app_base_url = _validate_url(
            web_app_base_url, field="WEB_APP_BASE_URL", allow_local_http=True
        )
        self.api_base_url = _validate_url(api_base_url, field="API_BASE_URL", allow_local_http=True)
        self.sse_base_url = _validate_url(sse_base_url, field="SSE_BASE_URL", allow_local_http=True)
        self.google_oauth_client_id = require_non_empty_string(
            google_oauth_client_id, "GOOGLE_OAUTH_CLIENT_ID"
        )
        self.google_oauth_client_secret_ref = require_non_empty_string(
            google_oauth_client_secret_ref, "GOOGLE_OAUTH_CLIENT_SECRET_REF"
        )
        self.google_oauth_callback_url = _validate_url(
            google_oauth_callback_url,
            field="GOOGLE_OAUTH_CALLBACK_URL",
            allow_local_http=True,
        )
        if self.google_oauth_callback_url != self.expected_google_oauth_callback_url:
            raise validation_failed(
                "GOOGLE_OAUTH_CALLBACK_URL",
                "Google OAuth callback URL must match the deployed API callback route.",
            )
        self.app_kms_key_id = require_non_empty_string(app_kms_key_id, "APP_KMS_KEY_ID")
        self.oauth_token_table_name = require_non_empty_string(
            oauth_token_table_name, "OAUTH_TOKEN_TABLE_NAME"
        )

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> "AuthRuntimeConfig":
        return cls(
            app_env=_required_config(values, "APP_ENV"),
            aws_region=_required_config(values, "AWS_REGION"),
            trusted_user_mode=_parse_bool(_required_config(values, "TRUSTED_USER_MODE")),
            allowed_origins=_split_csv(_required_config(values, "ALLOWED_ORIGINS")),
            web_app_base_url=_required_config(values, "WEB_APP_BASE_URL"),
            api_base_url=_required_config(values, "API_BASE_URL"),
            sse_base_url=_required_config(values, "SSE_BASE_URL"),
            google_oauth_client_id=_required_config(values, "GOOGLE_OAUTH_CLIENT_ID"),
            google_oauth_client_secret_ref=_required_config(
                values, "GOOGLE_OAUTH_CLIENT_SECRET_REF"
            ),
            google_oauth_callback_url=_required_config(values, "GOOGLE_OAUTH_CALLBACK_URL"),
            app_kms_key_id=_required_config(values, "APP_KMS_KEY_ID"),
            oauth_token_table_name=_required_config(values, "OAUTH_TOKEN_TABLE_NAME"),
        )

    @property
    def expected_google_oauth_callback_url(self) -> str:
        return f"{self.api_base_url.rstrip('/')}/oauth/google/callback"

    def google_oauth_flow_config(self) -> dict[str, Any]:
        return freeze(
            {
                "clientId": self.google_oauth_client_id,
                "redirectUri": self.google_oauth_callback_url,
                "allowedRedirectTargets": self.allowed_origins,
            }
        )

    def public_metadata(self) -> dict[str, Any]:
        return freeze(
            {
                "appEnv": self.app_env,
                "awsRegion": self.aws_region,
                "trustedUserMode": self.trusted_user_mode,
                "webAppBaseUrl": self.web_app_base_url,
                "apiBaseUrl": self.api_base_url,
                "sseBaseUrl": self.sse_base_url,
                "googleOAuthCallbackUrl": self.google_oauth_callback_url,
                "allowedOrigins": self.allowed_origins,
                "oauthTokenTableName": self.oauth_token_table_name,
            }
        )


class AuthRouteAuthorizer:
    def __init__(self, *, identity_service: Any) -> None:
        if identity_service is None or not callable(getattr(identity_service, "derive_identity", None)):
            raise TypeError("identityService.deriveIdentity is required.")
        if not callable(getattr(identity_service, "assert_authorized_reference", None)):
            raise TypeError("identityService.assertAuthorizedReference is required.")
        self.identity_service = identity_service

    def authorize_http_request(
        self,
        *,
        product_session: dict[str, Any] | None,
        client_identity: dict[str, Any] | None = None,
        reference: dict[str, Any] | None = None,
        reference_type: str | None = None,
    ) -> dict[str, Any]:
        identity = self.identity_service.derive_identity(
            product_session=product_session,
            client_identity=client_identity,
        )
        result = {"transport": "http", "identity": identity}
        if reference_type is not None:
            result["authorizedReference"] = self.identity_service.assert_authorized_reference(
                identity,
                reference,
                reference_type=reference_type,
            )
        return freeze(result)

    def authorize_sse_stream(
        self,
        *,
        product_session: dict[str, Any] | None,
        session_reference: dict[str, Any] | None,
        client_identity: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        identity = self.identity_service.derive_identity(
            product_session=product_session,
            client_identity=client_identity,
        )
        return freeze(
            {
                "transport": "sse",
                "identity": identity,
                "authorizedReference": self.identity_service.assert_authorized_reference(
                    identity,
                    session_reference,
                    reference_type=AUTH_REFERENCE_TYPES["SESSION"],
                ),
            }
        )


def _required_config(values: Mapping[str, Any], key: str) -> str:
    try:
        return require_non_empty_string(values.get(key), key)
    except TypeError:
        raise validation_failed(key, f"{key} is required.")


def _parse_bool(value: str) -> bool:
    return _coerce_bool(value)


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if not isinstance(value, str):
        raise validation_failed("TRUSTED_USER_MODE", "TRUSTED_USER_MODE must be a boolean value.")
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise validation_failed("TRUSTED_USER_MODE", "TRUSTED_USER_MODE must be a boolean value.")


def _split_csv(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _validate_url(value: str, *, field: str, allow_local_http: bool) -> str:
    url = require_non_empty_string(value, field).rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise validation_failed(field, f"{field} must be an absolute HTTP(S) URL.")
    if parsed.scheme == "http" and not (allow_local_http and parsed.hostname in _LOCAL_HOSTS):
        raise validation_failed(field, f"{field} must use HTTPS outside local testing.")
    if parsed.query or parsed.fragment:
        raise validation_failed(field, f"{field} must not include query or fragment components.")
    return url
