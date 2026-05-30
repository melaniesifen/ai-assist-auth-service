import {
  AUTH_ERROR_CODES,
  AuthError,
  forbidden,
  validationFailed
} from "./errors.js";
import { requireIdentity } from "./identity.js";
import { cloneDate, requireDate, requireNonEmptyString, toIso } from "./validation.js";

export const OAUTH_PROVIDERS = Object.freeze({
  GOOGLE: "google"
});

export const OAUTH_TOKEN_STATUS = Object.freeze({
  ACTIVE: "active",
  REVOKED: "revoked"
});

const OAUTH_TOKEN_PURPOSE = "oauth-token";

export class InMemoryOAuthTokenRepository {
  constructor() {
    this.records = new Map();
  }

  upsert(record) {
    this.records.set(tokenKey(record), cloneRecord(record));
    return cloneRecord(record);
  }

  get({ tenantId, userId, provider, googleAccountId }) {
    const record = this.records.get(tokenKey({ tenantId, userId, provider, googleAccountId }));
    return record ? cloneRecord(record) : null;
  }

  listForUser({ tenantId, userId, provider }) {
    return [...this.records.values()]
      .filter(
        (record) =>
          record.tenantId === tenantId &&
          record.userId === userId &&
          (!provider || record.provider === provider)
      )
      .map(cloneRecord);
  }
}

export class OAuthTokenService {
  constructor({ tenantDirectory, tokenRepository, tokenProtector, clock = () => new Date() }) {
    if (!tenantDirectory) {
      throw new TypeError("tenantDirectory is required.");
    }
    if (!tokenRepository) {
      throw new TypeError("tokenRepository is required.");
    }
    if (!tokenProtector || typeof tokenProtector.encrypt !== "function") {
      throw new TypeError("tokenProtector.encrypt is required.");
    }
    this.tenantDirectory = tenantDirectory;
    this.tokenRepository = tokenRepository;
    this.tokenProtector = tokenProtector;
    this.clock = clock;
  }

  connectGoogle({
    identity,
    googleAccountId,
    scopes,
    accessToken,
    refreshToken = null,
    expiresAt
  }) {
    requireIdentity(identity);
    this.tenantDirectory.assertActiveMembership(identity);
    requireNonEmptyString(googleAccountId, "googleAccountId");
    requireNonEmptyString(accessToken, "accessToken");
    const normalizedScopes = normalizeScopes(scopes);
    const now = this.clock();
    const tokenExpiresAt = requireDate(expiresAt, "expiresAt");
    const context = encryptionContext(identity, OAUTH_PROVIDERS.GOOGLE);
    const existing = this.tokenRepository.get({
      tenantId: identity.tenantId,
      userId: identity.userId,
      provider: OAUTH_PROVIDERS.GOOGLE,
      googleAccountId
    });

    const record = {
      tenantId: identity.tenantId,
      userId: identity.userId,
      provider: OAUTH_PROVIDERS.GOOGLE,
      googleAccountId,
      scopes: normalizedScopes,
      accessTokenCiphertext: this.tokenProtector.encrypt(accessToken, { context }),
      refreshTokenCiphertext: refreshToken
        ? this.tokenProtector.encrypt(refreshToken, { context })
        : existing?.refreshTokenCiphertext ?? null,
      expiresAt: cloneDate(tokenExpiresAt),
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
      revokedAt: null,
      status: OAUTH_TOKEN_STATUS.ACTIVE
    };
    return tokenMetadata(this.tokenRepository.upsert(record), now);
  }

  getGoogleStatus({ identity, googleAccountId }) {
    requireIdentity(identity);
    this.tenantDirectory.assertActiveMembership(identity);
    const records = googleAccountId
      ? [
          this.tokenRepository.get({
            tenantId: identity.tenantId,
            userId: identity.userId,
            provider: OAUTH_PROVIDERS.GOOGLE,
            googleAccountId
          })
        ].filter(Boolean)
      : this.tokenRepository.listForUser({
          tenantId: identity.tenantId,
          userId: identity.userId,
          provider: OAUTH_PROVIDERS.GOOGLE
        });

    const now = this.clock();
    const accounts = records.map((record) => tokenMetadata(record, now));
    return {
      tenantId: identity.tenantId,
      userId: identity.userId,
      provider: OAUTH_PROVIDERS.GOOGLE,
      connected: records.some((record) => isGoogleTokenAvailable(record, now)),
      accounts
    };
  }

  assertGoogleTokenUsable({ identity, googleAccountId }) {
    requireIdentity(identity);
    this.tenantDirectory.assertActiveMembership(identity);
    const record = this.tokenRepository.get({
      tenantId: identity.tenantId,
      userId: identity.userId,
      provider: OAUTH_PROVIDERS.GOOGLE,
      googleAccountId
    });
    if (!record) {
      throw new AuthError({
        code: AUTH_ERROR_CODES.OAUTH_TOKEN_NOT_FOUND,
        message: "Google OAuth connection is not available.",
        status: 403
      });
    }
    const now = this.clock();
    if (record.status !== OAUTH_TOKEN_STATUS.ACTIVE || record.revokedAt) {
      throw new AuthError({
        code: AUTH_ERROR_CODES.OAUTH_TOKEN_REVOKED,
        message: "Google OAuth connection must be reconnected.",
        status: 403
      });
    }
    if (!isGoogleTokenAvailable(record, now)) {
      throw new AuthError({
        code: AUTH_ERROR_CODES.OAUTH_TOKEN_REVOKED,
        message: "Google OAuth connection has expired and cannot be refreshed.",
        status: 403
      });
    }
    return tokenMetadata(record, now);
  }

  revokeGoogle({ identity, googleAccountId, revokedAt = this.clock() }) {
    requireIdentity(identity);
    this.tenantDirectory.assertActiveMembership(identity);
    const record = this.tokenRepository.get({
      tenantId: identity.tenantId,
      userId: identity.userId,
      provider: OAUTH_PROVIDERS.GOOGLE,
      googleAccountId
    });
    if (!record) {
      throw forbidden();
    }
    record.status = OAUTH_TOKEN_STATUS.REVOKED;
    record.revokedAt = cloneDate(revokedAt);
    record.updatedAt = cloneDate(revokedAt);
    record.accessTokenCiphertext = null;
    record.refreshTokenCiphertext = null;
    return tokenMetadata(this.tokenRepository.upsert(record), this.clock());
  }
}

function normalizeScopes(scopes) {
  if (!Array.isArray(scopes) || scopes.length === 0) {
    throw validationFailed("scopes", "At least one OAuth scope is required.");
  }
  const normalized = [...new Set(scopes.map((scope) => String(scope).trim()).filter(Boolean))].sort();
  if (normalized.length === 0) {
    throw validationFailed("scopes", "At least one OAuth scope is required.");
  }
  return normalized;
}

function encryptionContext(identity, provider) {
  return Object.freeze({
    tenantId: identity.tenantId,
    userId: identity.userId,
    provider,
    purpose: OAUTH_TOKEN_PURPOSE
  });
}

function tokenMetadata(record, now) {
  const isExpired = record.expiresAt <= now;
  const refreshAvailable = Boolean(record.refreshTokenCiphertext);
  const isAvailable = isGoogleTokenAvailable(record, now);
  return Object.freeze({
    tenantId: record.tenantId,
    userId: record.userId,
    provider: record.provider,
    googleAccountId: record.googleAccountId,
    scopes: [...record.scopes],
    status: record.status,
    isExpired,
    isAvailable,
    refreshRequired: isExpired && refreshAvailable && record.status === OAUTH_TOKEN_STATUS.ACTIVE,
    reconnectRequired: !isAvailable,
    expiresAt: toIso(record.expiresAt),
    createdAt: toIso(record.createdAt),
    updatedAt: toIso(record.updatedAt),
    revokedAt: toIso(record.revokedAt)
  });
}

function isGoogleTokenAvailable(record, now) {
  return (
    record.status === OAUTH_TOKEN_STATUS.ACTIVE &&
    !record.revokedAt &&
    (record.expiresAt > now || Boolean(record.refreshTokenCiphertext))
  );
}

function tokenKey({ tenantId, userId, provider, googleAccountId }) {
  return `${tenantId}:${userId}:${provider}:${googleAccountId}`;
}

function cloneRecord(record) {
  return {
    ...record,
    scopes: [...record.scopes],
    expiresAt: cloneDate(record.expiresAt),
    createdAt: cloneDate(record.createdAt),
    updatedAt: cloneDate(record.updatedAt),
    revokedAt: cloneDate(record.revokedAt)
  };
}
