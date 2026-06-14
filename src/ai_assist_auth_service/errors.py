from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping


AUTH_ERROR_CODES = MappingProxyType(
    {
        "AUTHENTICATION_REQUIRED": "AUTHENTICATION_REQUIRED",
        "INVALID_AUTH_TOKEN": "INVALID_AUTH_TOKEN",
        "AUTH_TOKEN_EXPIRED": "AUTH_TOKEN_EXPIRED",
        "AUTH_TOKEN_MALFORMED": "AUTH_TOKEN_MALFORMED",
        "TENANT_ACCESS_DENIED": "TENANT_ACCESS_DENIED",
        "TENANT_DISABLED": "TENANT_DISABLED",
        "USER_DISABLED": "USER_DISABLED",
        "OAUTH_STATE_INVALID": "OAUTH_STATE_INVALID",
        "OAUTH_EXCHANGE_FAILED": "OAUTH_EXCHANGE_FAILED",
        "OAUTH_REFRESH_FAILED": "OAUTH_REFRESH_FAILED",
        "OAUTH_TOKEN_NOT_FOUND": "OAUTH_TOKEN_NOT_FOUND",
        "OAUTH_TOKEN_REVOKED": "OAUTH_TOKEN_REVOKED",
        "VALIDATION_FAILED": "VALIDATION_FAILED",
    }
)


@dataclass(frozen=True)
class AuthError(Exception):
    code: str
    message: str
    status: int = 500
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        Exception.__init__(self, self.message)
        object.__setattr__(self, "name", "AuthError")
        object.__setattr__(self, "details", MappingProxyType(dict(self.details)))

    def to_response(self) -> dict[str, Any]:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "details": dict(self.details),
            },
            "status": self.status,
        }


def authentication_required(message: str = "Authentication is required.") -> AuthError:
    return AuthError(
        code=AUTH_ERROR_CODES["AUTHENTICATION_REQUIRED"],
        message=message,
        status=401,
    )


def invalid_auth_token(message: str = "The product auth token is invalid.") -> AuthError:
    return AuthError(
        code=AUTH_ERROR_CODES["INVALID_AUTH_TOKEN"],
        message=message,
        status=401,
    )


def expired_auth_token(message: str = "The product auth token has expired.") -> AuthError:
    return AuthError(
        code=AUTH_ERROR_CODES["AUTH_TOKEN_EXPIRED"],
        message=message,
        status=401,
    )


def malformed_auth_token(message: str = "The product auth token is malformed.") -> AuthError:
    return AuthError(
        code=AUTH_ERROR_CODES["AUTH_TOKEN_MALFORMED"],
        message=message,
        status=401,
    )


def forbidden(message: str = "The requested reference is not authorized.") -> AuthError:
    return AuthError(
        code=AUTH_ERROR_CODES["TENANT_ACCESS_DENIED"],
        message=message,
        status=403,
    )


def validation_failed(field: str, message: str) -> AuthError:
    return AuthError(
        code=AUTH_ERROR_CODES["VALIDATION_FAILED"],
        message=message,
        status=400,
        details={"field": field},
    )
