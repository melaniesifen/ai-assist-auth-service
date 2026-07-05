from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_assist_auth_service import (  # noqa: E402
    AUTH_ERROR_CODES,
    MEMBERSHIP_STATUS,
    TENANT_ROLES,
    TENANT_STATUS,
    USER_STATUS,
    AuthError,
    AuthSetupStatusService,
    IdentityService,
    InMemoryOAuthTokenRepository,
    InMemoryTenantDirectory,
    OAuthTokenService,
)


BASE_TIME = datetime(2026, 5, 29, 12, 0, 0, tzinfo=timezone.utc)
LATER_TIME = datetime(2026, 5, 29, 13, 0, 0, tzinfo=timezone.utc)
SESSION_EXPIRES_AT = datetime(2026, 5, 29, 14, 0, 0, tzinfo=timezone.utc)


class AuthFixture:
    def __init__(
        self,
        *,
        tenant_directory: InMemoryTenantDirectory,
        identity_service: IdentityService,
        oauth_token_service: OAuthTokenService,
        setup_status_service: AuthSetupStatusService,
        token_exchange: FakeGoogleTokenExchange,
        token_protector: FakeTokenProtector,
        token_repository: InMemoryOAuthTokenRepository,
    ) -> None:
        self.tenant_directory = tenant_directory
        self.identity_service = identity_service
        self.oauth_token_service = oauth_token_service
        self.setup_status_service = setup_status_service
        self.token_exchange = token_exchange
        self.token_protector = token_protector
        self.token_repository = token_repository


def create_auth_fixture(
    *,
    tenant_status: str = TENANT_STATUS["ACTIVE"],
    user_status: str = USER_STATUS["ACTIVE"],
    membership_status: str = MEMBERSHIP_STATUS["ACTIVE"],
) -> AuthFixture:
    tenant_directory = InMemoryTenantDirectory()
    tenant_directory.put_tenant(
        tenant_id="tenant-1", status=tenant_status, created_at=BASE_TIME
    )
    tenant_directory.put_user(
        user_id="user-1",
        status=user_status,
        default_tenant_id="tenant-1",
        created_at=BASE_TIME,
    )
    tenant_directory.put_membership(
        tenant_id="tenant-1",
        user_id="user-1",
        role=TENANT_ROLES["OWNER"],
        status=membership_status,
        created_at=BASE_TIME,
    )
    token_repository = InMemoryOAuthTokenRepository()
    token_protector = FakeTokenProtector()
    token_exchange = FakeGoogleTokenExchange()
    identity_service = IdentityService(
        tenant_directory=tenant_directory,
        clock=lambda: BASE_TIME,
        expected_audience="ai-assist",
    )
    oauth_token_service = OAuthTokenService(
        tenant_directory=tenant_directory,
        token_repository=token_repository,
        token_protector=token_protector,
        token_exchange=token_exchange,
        clock=lambda: BASE_TIME,
    )
    setup_status_service = AuthSetupStatusService(
        identity_service=identity_service,
        oauth_token_service=oauth_token_service,
        clock=lambda: BASE_TIME,
    )
    return AuthFixture(
        tenant_directory=tenant_directory,
        identity_service=identity_service,
        oauth_token_service=oauth_token_service,
        setup_status_service=setup_status_service,
        token_exchange=token_exchange,
        token_protector=token_protector,
        token_repository=token_repository,
    )


def product_session(**overrides: object) -> dict[str, object]:
    session = {
        "tenantId": "tenant-1",
        "userId": "user-1",
        "authSubject": "auth0|subject-1",
        "audience": "ai-assist",
        "sessionId": "session-1",
        "expiresAt": SESSION_EXPIRES_AT,
        "requestId": "req-1",
        "correlationId": "corr-1",
    }
    session.update(overrides)
    return session


class FakeTokenProtector:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.ciphertexts: dict[str, str] = {}

    def encrypt(self, plaintext: str, *, context: dict[str, str]) -> str:
        self.calls.append({"plaintext": plaintext, "context": context})
        ciphertext = f"encrypted:{context['purpose']}:{len(plaintext)}"
        self.ciphertexts[ciphertext] = plaintext
        return ciphertext

    def decrypt(self, ciphertext: str, *, context: dict[str, str]) -> str:
        self.calls.append({"ciphertext": ciphertext, "context": context})
        return self.ciphertexts[ciphertext]


class FakeGoogleTokenExchange:
    def __init__(self) -> None:
        self.exchange_response: dict[str, object] = {
            "googleAccountId": "google-account-1",
            "scopes": ["https://www.googleapis.com/auth/documents"],
            "accessToken": "access-token-secret",
            "refreshToken": "refresh-token-secret",
            "expiresAt": LATER_TIME,
        }
        self.refresh_response: dict[str, object] = {
            "accessToken": "refreshed-access-token-secret",
            "expiresAt": LATER_TIME,
        }
        self.fail_exchange = False
        self.fail_refresh = False
        self.exchange_exception: Exception | None = None
        self.exchange_calls: list[dict[str, object]] = []
        self.refresh_calls: list[dict[str, object]] = []

    def exchange_code(self, *, authorization_code: str, redirect_uri: str) -> dict[str, object]:
        self.exchange_calls.append(
            {"authorizationCode": authorization_code, "redirectUri": redirect_uri}
        )
        if self.exchange_exception is not None:
            raise self.exchange_exception
        if self.fail_exchange:
            raise RuntimeError("exchange failed")
        return dict(self.exchange_response)

    def refresh(self, *, refresh_token: str, scopes: list[str]) -> dict[str, object]:
        self.refresh_calls.append({"refreshToken": refresh_token, "scopes": list(scopes)})
        if self.fail_refresh:
            raise RuntimeError("refresh failed")
        return dict(self.refresh_response)


def assert_auth_error(
    test_case: unittest.TestCase,
    fn: object,
    code: str,
    status: int,
) -> None:
    with test_case.assertRaises(AuthError) as caught:
        fn()
    test_case.assertEqual(caught.exception.name, "AuthError")
    test_case.assertEqual(caught.exception.code, code)
    test_case.assertEqual(caught.exception.status, status)
