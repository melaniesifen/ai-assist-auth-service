import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  AUTH_ERROR_CODES,
  IdentityService,
  InMemoryOAuthTokenRepository,
  InMemoryTenantDirectory,
  MEMBERSHIP_STATUS,
  OAuthTokenService,
  TENANT_ROLES,
  TENANT_STATUS,
  USER_STATUS
} from "../src/index.js";

const BASE_TIME = new Date("2026-05-29T12:00:00.000Z");
const LATER_TIME = new Date("2026-05-29T13:00:00.000Z");
const SESSION_EXPIRES_AT = new Date("2026-05-29T14:00:00.000Z");

describe("IdentityService", () => {
  it("derives identity from the product session and records ignored client identity", () => {
    const { identityService } = createAuthFixture();

    const identity = identityService.deriveIdentity({
      productSession: productSession(),
      clientIdentity: { tenantId: "attacker-tenant", userId: "attacker-user" }
    });

    assert.equal(identity.tenantId, "tenant-1");
    assert.equal(identity.userId, "user-1");
    assert.equal(identity.authSubject, "auth0|subject-1");
    assert.equal(identity.membership.role, TENANT_ROLES.OWNER);
    assert.deepEqual(identity.ignoredClientIdentity, {
      tenantId: "attacker-tenant",
      userId: "attacker-user"
    });
  });

  it("rejects missing and expired product sessions with typed auth errors", () => {
    const { identityService } = createAuthFixture();

    assertAuthError(
      () => identityService.deriveIdentity(),
      AUTH_ERROR_CODES.AUTHENTICATION_REQUIRED,
      401
    );
    assertAuthError(
      () =>
        identityService.deriveIdentity({
          productSession: productSession({ expiresAt: new Date("2026-05-29T11:00:00.000Z") })
        }),
      AUTH_ERROR_CODES.INVALID_AUTH_TOKEN,
      401
    );
  });

  it("rejects malformed product session claims with typed auth errors", () => {
    const { identityService } = createAuthFixture();
    const malformedSessions = [
      productSession({ tenantId: "" }),
      productSession({ userId: "   " }),
      productSession({ authSubject: null }),
      productSession({ expiresAt: "not-a-date" })
    ];

    for (const malformedSession of malformedSessions) {
      assertAuthError(
        () => identityService.deriveIdentity({ productSession: malformedSession }),
        AUTH_ERROR_CODES.INVALID_AUTH_TOKEN,
        401
      );
    }
  });

  it("rejects disabled tenants, disabled users, and inactive memberships before access", () => {
    const disabledTenant = createAuthFixture({ tenantStatus: TENANT_STATUS.DISABLED });
    assertAuthError(
      () => disabledTenant.identityService.deriveIdentity({ productSession: productSession() }),
      AUTH_ERROR_CODES.TENANT_DISABLED,
      403
    );

    const disabledUser = createAuthFixture({ userStatus: USER_STATUS.DISABLED });
    assertAuthError(
      () => disabledUser.identityService.deriveIdentity({ productSession: productSession() }),
      AUTH_ERROR_CODES.USER_DISABLED,
      403
    );

    const disabledMembership = createAuthFixture({
      membershipStatus: MEMBERSHIP_STATUS.DISABLED
    });
    assertAuthError(
      () => disabledMembership.identityService.deriveIdentity({ productSession: productSession() }),
      AUTH_ERROR_CODES.TENANT_ACCESS_DENIED,
      403
    );
  });

  it("rejects cross-tenant references without leaking existence", () => {
    const { identityService } = createAuthFixture();
    const identity = identityService.deriveIdentity({ productSession: productSession() });

    assertAuthError(
      () => identityService.assertSameTenant(identity, "tenant-2"),
      AUTH_ERROR_CODES.TENANT_ACCESS_DENIED,
      403
    );
  });
});

describe("OAuthTokenService", () => {
  it("stores Google OAuth tokens with encryption context and returns metadata only", () => {
    const { identityService, oauthTokenService, tokenProtector } = createAuthFixture();
    const identity = identityService.deriveIdentity({ productSession: productSession() });

    const metadata = oauthTokenService.connectGoogle({
      identity,
      googleAccountId: "google-account-1",
      scopes: ["docs.read", "docs.read", "drive.file"],
      accessToken: "access-token-secret",
      refreshToken: "refresh-token-secret",
      expiresAt: LATER_TIME
    });

    assert.equal(metadata.provider, "google");
    assert.equal(metadata.status, "active");
    assert.deepEqual(metadata.scopes, ["docs.read", "drive.file"]);
    assert.equal(metadata.isExpired, false);
    assert.equal(metadata.accessToken, undefined);
    assert.equal(metadata.refreshToken, undefined);
    assert.equal(metadata.accessTokenCiphertext, undefined);
    assert.equal(tokenProtector.calls.length, 2);
    assert.deepEqual(tokenProtector.calls[0].context, {
      tenantId: "tenant-1",
      userId: "user-1",
      provider: "google",
      purpose: "oauth-token"
    });
  });

  it("returns status metadata without exposing token material", () => {
    const { identityService, oauthTokenService } = createAuthFixture();
    const identity = identityService.deriveIdentity({ productSession: productSession() });
    oauthTokenService.connectGoogle({
      identity,
      googleAccountId: "google-account-1",
      scopes: ["docs.read"],
      accessToken: "access-token-secret",
      refreshToken: "refresh-token-secret",
      expiresAt: LATER_TIME
    });

    const status = oauthTokenService.getGoogleStatus({ identity });

    assert.equal(status.connected, true);
    assert.equal(status.accounts.length, 1);
    assert.equal(status.accounts[0].googleAccountId, "google-account-1");
    assert.equal(JSON.stringify(status).includes("secret"), false);
  });

  it("reports expired non-refreshable Google tokens as reconnect required", () => {
    const { identityService, oauthTokenService } = createAuthFixture();
    const identity = identityService.deriveIdentity({ productSession: productSession() });
    oauthTokenService.connectGoogle({
      identity,
      googleAccountId: "google-account-1",
      scopes: ["docs.read"],
      accessToken: "access-token-secret",
      expiresAt: new Date("2026-05-29T11:59:59.000Z")
    });

    const status = oauthTokenService.getGoogleStatus({ identity });

    assert.equal(status.connected, false);
    assert.equal(status.accounts[0].isAvailable, false);
    assert.equal(status.accounts[0].reconnectRequired, true);
    assertAuthError(
      () => oauthTokenService.assertGoogleTokenUsable({ identity, googleAccountId: "google-account-1" }),
      AUTH_ERROR_CODES.OAUTH_TOKEN_REVOKED,
      403
    );
  });

  it("marks revoked tokens unusable and clears stored ciphertext", () => {
    const { identityService, oauthTokenService, tokenRepository } = createAuthFixture();
    const identity = identityService.deriveIdentity({ productSession: productSession() });
    oauthTokenService.connectGoogle({
      identity,
      googleAccountId: "google-account-1",
      scopes: ["docs.read"],
      accessToken: "access-token-secret",
      refreshToken: "refresh-token-secret",
      expiresAt: LATER_TIME
    });

    const revoked = oauthTokenService.revokeGoogle({
      identity,
      googleAccountId: "google-account-1"
    });

    assert.equal(revoked.status, "revoked");
    assertAuthError(
      () => oauthTokenService.assertGoogleTokenUsable({ identity, googleAccountId: "google-account-1" }),
      AUTH_ERROR_CODES.OAUTH_TOKEN_REVOKED,
      403
    );
    const stored = tokenRepository.get({
      tenantId: "tenant-1",
      userId: "user-1",
      provider: "google",
      googleAccountId: "google-account-1"
    });
    assert.equal(stored.accessTokenCiphertext, null);
    assert.equal(stored.refreshTokenCiphertext, null);
  });

  it("does not expose OAuth tokens to another active same-tenant user", () => {
    const { identityService, oauthTokenService, tenantDirectory } = createAuthFixture();
    const identity = identityService.deriveIdentity({ productSession: productSession() });
    oauthTokenService.connectGoogle({
      identity,
      googleAccountId: "google-account-1",
      scopes: ["docs.read"],
      accessToken: "access-token-secret",
      refreshToken: "refresh-token-secret",
      expiresAt: LATER_TIME
    });
    tenantDirectory.putUser({
      userId: "user-2",
      defaultTenantId: "tenant-1",
      createdAt: BASE_TIME
    });
    tenantDirectory.putMembership({
      tenantId: "tenant-1",
      userId: "user-2",
      role: TENANT_ROLES.MEMBER,
      createdAt: BASE_TIME
    });

    const otherIdentity = {
      tenantId: "tenant-1",
      userId: "user-2",
      authSubject: "auth0|subject-2"
    };

    const status = oauthTokenService.getGoogleStatus({
      identity: otherIdentity,
      googleAccountId: "google-account-1"
    });

    assert.equal(status.connected, false);
    assert.deepEqual(status.accounts, []);
  });
});

function createAuthFixture({
  tenantStatus = TENANT_STATUS.ACTIVE,
  userStatus = USER_STATUS.ACTIVE,
  membershipStatus = MEMBERSHIP_STATUS.ACTIVE
} = {}) {
  const tenantDirectory = new InMemoryTenantDirectory();
  tenantDirectory.putTenant({ tenantId: "tenant-1", status: tenantStatus, createdAt: BASE_TIME });
  tenantDirectory.putUser({
    userId: "user-1",
    status: userStatus,
    defaultTenantId: "tenant-1",
    createdAt: BASE_TIME
  });
  tenantDirectory.putMembership({
    tenantId: "tenant-1",
    userId: "user-1",
    role: TENANT_ROLES.OWNER,
    status: membershipStatus,
    createdAt: BASE_TIME
  });
  const tokenRepository = new InMemoryOAuthTokenRepository();
  const tokenProtector = fakeTokenProtector();
  const identityService = new IdentityService({
    tenantDirectory,
    clock: () => BASE_TIME,
    expectedAudience: "ai-assist"
  });
  const oauthTokenService = new OAuthTokenService({
    tenantDirectory,
    tokenRepository,
    tokenProtector,
    clock: () => BASE_TIME
  });
  return { tenantDirectory, identityService, oauthTokenService, tokenProtector, tokenRepository };
}

function productSession(overrides = {}) {
  return {
    tenantId: "tenant-1",
    userId: "user-1",
    authSubject: "auth0|subject-1",
    audience: "ai-assist",
    expiresAt: SESSION_EXPIRES_AT,
    requestId: "req-1",
    correlationId: "corr-1",
    ...overrides
  };
}

function fakeTokenProtector() {
  const calls = [];
  return {
    calls,
    encrypt(plaintext, { context }) {
      calls.push({ plaintext, context });
      return `encrypted:${context.purpose}:${plaintext.length}`;
    }
  };
}

function assertAuthError(fn, code, status) {
  assert.throws(
    fn,
    (error) => error?.name === "AuthError" && error.code === code && error.status === status
  );
}
