from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs, urlparse

from .aws_adapters import (
    AwsClientFactory,
    DynamoDbOAuthTokenRepository,
    KmsTokenProtector,
    SecretsManagerSecretResolver,
)
from .allowed_users import (
    DEFAULT_ALLOWED_USERS_ENV,
    AllowedProductUserDirectory,
    TrustedEdgeJwtSessionMapper,
)
from .errors import AUTH_ERROR_CODES, AuthError, authentication_required, validation_failed
from .google_oauth_adapter import GoogleOAuthHttpTokenExchange
from .identity import IdentityService
from .oauth_flow import GoogleOAuthFlowService, InMemoryOAuthStateRepository, SignedOAuthStateCodec
from .oauth_tokens import InMemoryOAuthTokenRepository, OAuthTokenService
from .product_session import HmacProductSessionCodec, InMemorySessionRevocationRepository
from .runtime import AuthRuntimeConfig
from .setup_status import AuthSetupStatusService
from .tenancy import InMemoryTenantDirectory, TENANT_ROLES
from .validation import freeze, require_non_empty_string


class AuthHttpApplication:
    def __init__(
        self,
        *,
        runtime_config: AuthRuntimeConfig,
        tenant_directory: Any,
        identity_service: IdentityService,
        oauth_token_service: OAuthTokenService,
        oauth_flow_service: GoogleOAuthFlowService,
        setup_status_service: AuthSetupStatusService,
        product_session_codec: HmacProductSessionCodec,
        trusted_user_tenant_id: str,
        trusted_user_user_id: str,
        trusted_user_auth_subject: str,
        trusted_user_bootstrap_secret: str | None = None,
        trusted_edge_jwt_sessions: TrustedEdgeJwtSessionMapper | None = None,
    ) -> None:
        self.runtime_config = runtime_config
        self.tenant_directory = tenant_directory
        self.identity_service = identity_service
        self.oauth_token_service = oauth_token_service
        self.oauth_flow_service = oauth_flow_service
        self.setup_status_service = setup_status_service
        self.product_session_codec = product_session_codec
        self.trusted_edge_jwt_sessions = trusted_edge_jwt_sessions
        self.trusted_user_tenant_id = trusted_user_tenant_id
        self.trusted_user_user_id = trusted_user_user_id
        self.trusted_user_auth_subject = trusted_user_auth_subject
        self.trusted_user_bootstrap_secret = trusted_user_bootstrap_secret

    def handle(
        self,
        *,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        query: dict[str, list[str]] | None = None,
        body: bytes | str | None = None,
    ) -> dict[str, Any]:
        headers = _normalize_headers(headers or {})
        query = query or {}
        try:
            if method == "POST" and path == "/auth/login":
                return self._login(headers=headers, body=_json_body(body))
            if method == "POST" and path == "/auth/logout":
                return self._logout(headers=headers)
            if method == "GET" and path == "/auth/session":
                return _json_response(200, self._session(headers=headers))
            if method == "POST" and path == "/oauth/google/start":
                return self._oauth_start(headers=headers, body=_json_body(body))
            if method == "GET" and path == "/oauth/google/callback":
                return self._oauth_callback(query=query)
            if method == "GET" and path == "/oauth/google/status":
                return _json_response(200, self._google_status(headers=headers, query=query))
            if method == "DELETE" and path == "/oauth/google/connection":
                return _json_response(200, self._google_disconnect(headers=headers, query=query, body=_json_body(body)))
            return _json_response(
                404,
                {
                    "error": {
                        "code": "ROUTE_NOT_FOUND",
                        "message": "Route is not implemented by the auth service.",
                    }
                },
            )
        except AuthError as error:
            return _json_response(error.status, {"error": error.to_response()["error"]})
        except (TypeError, ValueError, json.JSONDecodeError):
            error = validation_failed("request", "Request is malformed.")
            return _json_response(error.status, {"error": error.to_response()["error"]})

    def _login(self, *, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        if not self.trusted_user_bootstrap_secret:
            raise AuthError(
                code=AUTH_ERROR_CODES["AUTHENTICATION_REQUIRED"],
                message="Trusted-user login bootstrap is not configured.",
                status=503,
            )
        if body.get("bootstrapSecret") != self.trusted_user_bootstrap_secret:
            raise authentication_required("Trusted-user bootstrap secret is invalid.")
        issued = self.product_session_codec.issue(
            tenant_id=self.trusted_user_tenant_id,
            user_id=self.trusted_user_user_id,
            auth_subject=self.trusted_user_auth_subject,
            request_id=headers.get("x-request-id"),
            correlation_id=headers.get("x-correlation-id"),
        )
        return _json_response(
            200,
            {
                "tokenType": "Bearer",
                "accessToken": issued["token"],
                "session": _public_session(issued["productSession"]),
            },
        )

    def _logout(self, *, headers: dict[str, str]) -> dict[str, Any]:
        token = _bearer_token(headers)
        self.product_session_codec.revoke(token)
        return _json_response(200, {"status": "logged_out"})

    def _session(self, *, headers: dict[str, str]) -> dict[str, Any]:
        product_session = self._product_session(headers)
        return self.setup_status_service.get_setup_status(product_session=product_session)

    def _oauth_start(self, *, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        identity = self.identity_service.derive_identity(product_session=self._product_session(headers))
        redirect_target = body.get("redirectTarget") or self.runtime_config.web_app_base_url
        started = self.oauth_flow_service.start_google_oauth(
            identity=identity,
            redirect_target=redirect_target,
        )
        return _json_response(200, started)

    def _oauth_callback(self, *, query: dict[str, list[str]]) -> dict[str, Any]:
        if _first(query, "error"):
            raise AuthError(
                code=AUTH_ERROR_CODES["OAUTH_EXCHANGE_FAILED"],
                message="Google OAuth callback returned an error.",
                status=400,
            )
        state = require_non_empty_string(_first(query, "state"), "state")
        code = require_non_empty_string(_first(query, "code"), "code")
        payload = self.oauth_flow_service.state_codec.verify(state)
        identity = {
            "tenantId": require_non_empty_string(payload.get("tenantId"), "state.tenantId"),
            "userId": require_non_empty_string(payload.get("userId"), "state.userId"),
            "authSubject": require_non_empty_string(
                payload.get("authSubject", payload.get("userId")), "state.authSubject"
            ),
        }
        connected = self.oauth_flow_service.complete_google_oauth(
            identity=identity,
            state=state,
            authorization_code=code,
        )
        location = f"{connected['redirectTarget']}?googleOAuth=connected"
        return {
            "status": 302,
            "headers": {"Location": location, "Cache-Control": "no-store"},
            "body": b"",
        }

    def _google_status(self, *, headers: dict[str, str], query: dict[str, list[str]]) -> dict[str, Any]:
        identity = self.identity_service.derive_identity(product_session=self._product_session(headers))
        return self.oauth_token_service.get_google_status(
            identity=identity,
            google_account_id=_first(query, "googleAccountId"),
        )

    def _google_disconnect(
        self,
        *,
        headers: dict[str, str],
        query: dict[str, list[str]],
        body: dict[str, Any],
    ) -> dict[str, Any]:
        identity = self.identity_service.derive_identity(product_session=self._product_session(headers))
        google_account_id = _first(query, "googleAccountId") or body.get("googleAccountId")
        if not google_account_id:
            accounts = self.oauth_token_service.get_google_status(identity=identity)["accounts"]
            if len(accounts) != 1:
                raise validation_failed(
                    "googleAccountId", "googleAccountId is required when multiple or no accounts exist."
                )
            google_account_id = accounts[0]["googleAccountId"]
        return self.oauth_token_service.disconnect_google(
            identity=identity,
            google_account_id=google_account_id,
        )

    def _product_session(self, headers: dict[str, str]) -> dict[str, Any]:
        if headers.get("x-ai-assist-auth-subject") and self.trusted_edge_jwt_sessions is not None:
            product_session = self.trusted_edge_jwt_sessions.product_session_from_headers(headers)
        else:
            product_session = self.product_session_codec.verify_bearer(headers.get("authorization"))
        product_session["requestId"] = headers.get("x-request-id") or product_session.get("requestId")
        product_session["correlationId"] = headers.get("x-correlation-id") or product_session.get("correlationId")
        return product_session


def create_app_from_env(env: dict[str, str] | None = None) -> AuthHttpApplication:
    env = env or dict(os.environ)
    runtime_config = AuthRuntimeConfig.from_mapping(env)
    allowed_users = AllowedProductUserDirectory.from_json(env.get(DEFAULT_ALLOWED_USERS_ENV))
    tenant_directory = _bootstrap_tenant_directory(env, allowed_users=allowed_users)
    revocations = InMemorySessionRevocationRepository()
    product_sessions = HmacProductSessionCodec(
        signing_secret=_required_mapping(env, "PRODUCT_AUTH_HMAC_SECRET"),
        audience=_required_mapping(env, "PRODUCT_AUTH_AUDIENCE"),
        ttl=timedelta(hours=int(env.get("PRODUCT_SESSION_TTL_HOURS", "8"))),
        revocations=revocations,
    )
    identity_service = IdentityService(
        tenant_directory=tenant_directory,
        expected_audience=_required_mapping(env, "PRODUCT_AUTH_AUDIENCE"),
    )
    aws = AwsClientFactory(region_name=env.get("AWS_REGION"))
    token_repository = (
        DynamoDbOAuthTokenRepository(
            table=aws.resource("dynamodb").Table(_required_mapping(env, "OAUTH_TOKEN_TABLE_NAME"))
        )
        if env.get("OAUTH_TOKEN_TABLE_NAME")
        else InMemoryOAuthTokenRepository()
    )
    token_protector = KmsTokenProtector(
        client=aws.client("kms"),
        key_id=_required_mapping(env, "APP_KMS_KEY_ID"),
    )
    secret_resolver = SecretsManagerSecretResolver(client=aws.client("secretsmanager"))
    token_exchange = GoogleOAuthHttpTokenExchange(
        client_id=_required_mapping(env, "GOOGLE_OAUTH_CLIENT_ID"),
        client_secret_resolver=secret_resolver,
        client_secret_ref=_required_mapping(env, "GOOGLE_OAUTH_CLIENT_SECRET_REF"),
    )
    oauth_token_service = OAuthTokenService(
        tenant_directory=tenant_directory,
        token_repository=token_repository,
        token_protector=token_protector,
        token_exchange=token_exchange,
    )
    oauth_flow_service = GoogleOAuthFlowService(
        oauth_token_service=oauth_token_service,
        state_repository=InMemoryOAuthStateRepository(),
        state_codec=SignedOAuthStateCodec(
            signing_secret=_required_mapping(env, "OAUTH_STATE_SIGNING_SECRET")
        ),
        token_exchange=token_exchange,
        client_id=runtime_config.google_oauth_client_id,
        redirect_uri=runtime_config.google_oauth_callback_url,
        allowed_redirect_targets=runtime_config.allowed_origins,
        nonce_factory=lambda: os.urandom(18).hex(),
    )
    setup_status_service = AuthSetupStatusService(
        identity_service=identity_service,
        oauth_token_service=oauth_token_service,
    )
    return AuthHttpApplication(
        runtime_config=runtime_config,
        tenant_directory=tenant_directory,
        identity_service=identity_service,
        oauth_token_service=oauth_token_service,
        oauth_flow_service=oauth_flow_service,
        setup_status_service=setup_status_service,
        product_session_codec=product_sessions,
        trusted_user_tenant_id=_required_mapping(env, "TRUSTED_USER_TENANT_ID"),
        trusted_user_user_id=_required_mapping(env, "TRUSTED_USER_USER_ID"),
        trusted_user_auth_subject=_required_mapping(env, "TRUSTED_USER_AUTH_SUBJECT"),
        trusted_user_bootstrap_secret=env.get("TRUSTED_USER_BOOTSTRAP_SECRET"),
        trusted_edge_jwt_sessions=TrustedEdgeJwtSessionMapper(
            allowed_users=allowed_users,
            audience=_required_mapping(env, "PRODUCT_AUTH_AUDIENCE"),
            issuer=_required_mapping(env, "PRODUCT_AUTH_ISSUER"),
        ),
    )


_APP: AuthHttpApplication | None = None


def handle_http_request(
    *,
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    query_string: str = "",
    body: bytes | None = None,
) -> dict[str, Any]:
    global _APP
    if _APP is None:
        _APP = create_app_from_env()
    parsed = urlparse(path)
    query = parse_qs(query_string or parsed.query)
    clean_path = parsed.path
    return _APP.handle(
        method=method,
        path=clean_path,
        headers=headers,
        query=query,
        body=body,
    )


def _bootstrap_tenant_directory(
    env: dict[str, str],
    *,
    allowed_users: AllowedProductUserDirectory | None = None,
) -> InMemoryTenantDirectory:
    tenant_directory = InMemoryTenantDirectory()
    if allowed_users is not None:
        allowed_users.seed_tenant_directory(tenant_directory)
    tenant_id = _required_mapping(env, "TRUSTED_USER_TENANT_ID")
    user_id = _required_mapping(env, "TRUSTED_USER_USER_ID")
    tenant_directory.put_tenant(tenant_id=tenant_id)
    tenant_directory.put_user(user_id=user_id, default_tenant_id=tenant_id)
    tenant_directory.put_membership(
        tenant_id=tenant_id,
        user_id=user_id,
        role=env.get("TRUSTED_USER_TENANT_ROLE", TENANT_ROLES["OWNER"]),
    )
    return tenant_directory


def _json_body(body: bytes | str | None) -> dict[str, Any]:
    if body in {None, b"", ""}:
        return {}
    raw = body.decode("utf-8") if isinstance(body, bytes) else body
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        raise validation_failed("body", "JSON request body is malformed.")
    if not isinstance(parsed, dict):
        raise validation_failed("body", "JSON request body must be an object.")
    return parsed


def _json_response(status: int, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {"Content-Type": "application/json", "Cache-Control": "no-store"},
        "body": json.dumps(freeze(payload), separators=(",", ":"), sort_keys=True).encode("utf-8"),
    }


def _normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    return {str(key).lower(): value for key, value in headers.items()}


def _bearer_token(headers: dict[str, str]) -> str:
    authorization = headers.get("authorization")
    if not authorization or not authorization.startswith("Bearer "):
        raise authentication_required("Bearer product session token is required.")
    return authorization[len("Bearer ") :].strip()


def _first(query: dict[str, list[str]], name: str) -> str | None:
    values = query.get(name) or []
    return values[0] if values else None


def _public_session(product_session: dict[str, Any]) -> dict[str, Any]:
    return {
        "tenantId": product_session["tenantId"],
        "userId": product_session["userId"],
        "authSubject": product_session["authSubject"],
        "sessionId": product_session["sessionId"],
        "expiresAt": product_session["expiresAt"],
    }


def _required_mapping(values: dict[str, str], key: str) -> str:
    return require_non_empty_string(values.get(key), key)
