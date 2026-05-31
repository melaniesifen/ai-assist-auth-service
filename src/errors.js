export const AUTH_ERROR_CODES = Object.freeze({
  AUTHENTICATION_REQUIRED: "AUTHENTICATION_REQUIRED",
  INVALID_AUTH_TOKEN: "INVALID_AUTH_TOKEN",
  AUTH_TOKEN_EXPIRED: "AUTH_TOKEN_EXPIRED",
  AUTH_TOKEN_MALFORMED: "AUTH_TOKEN_MALFORMED",
  TENANT_ACCESS_DENIED: "TENANT_ACCESS_DENIED",
  TENANT_DISABLED: "TENANT_DISABLED",
  USER_DISABLED: "USER_DISABLED",
  OAUTH_STATE_INVALID: "OAUTH_STATE_INVALID",
  OAUTH_TOKEN_NOT_FOUND: "OAUTH_TOKEN_NOT_FOUND",
  OAUTH_TOKEN_REVOKED: "OAUTH_TOKEN_REVOKED",
  VALIDATION_FAILED: "VALIDATION_FAILED"
});

export class AuthError extends Error {
  constructor({ code, message, status = 500, details = {} }) {
    super(message);
    this.name = "AuthError";
    this.code = code;
    this.status = status;
    this.details = Object.freeze({ ...details });
  }

  toResponse() {
    return {
      error: {
        code: this.code,
        message: this.message,
        details: this.details
      },
      status: this.status
    };
  }
}

export function authenticationRequired(message = "Authentication is required.") {
  return new AuthError({
    code: AUTH_ERROR_CODES.AUTHENTICATION_REQUIRED,
    message,
    status: 401
  });
}

export function invalidAuthToken(message = "The product auth token is invalid.") {
  return new AuthError({
    code: AUTH_ERROR_CODES.INVALID_AUTH_TOKEN,
    message,
    status: 401
  });
}

export function expiredAuthToken(message = "The product auth token has expired.") {
  return new AuthError({
    code: AUTH_ERROR_CODES.AUTH_TOKEN_EXPIRED,
    message,
    status: 401
  });
}

export function malformedAuthToken(message = "The product auth token is malformed.") {
  return new AuthError({
    code: AUTH_ERROR_CODES.AUTH_TOKEN_MALFORMED,
    message,
    status: 401
  });
}

export function forbidden(message = "The requested reference is not authorized.") {
  return new AuthError({
    code: AUTH_ERROR_CODES.TENANT_ACCESS_DENIED,
    message,
    status: 403
  });
}

export function validationFailed(field, message) {
  return new AuthError({
    code: AUTH_ERROR_CODES.VALIDATION_FAILED,
    message,
    status: 400,
    details: { field }
  });
}
