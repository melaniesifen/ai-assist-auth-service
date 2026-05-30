import { authenticationRequired, forbidden, invalidAuthToken } from "./errors.js";
import { requireDate, requireNonEmptyString, toIso } from "./validation.js";

export class IdentityService {
  constructor({ tenantDirectory, clock = () => new Date(), expectedAudience = null }) {
    if (!tenantDirectory) {
      throw new TypeError("tenantDirectory is required.");
    }
    this.tenantDirectory = tenantDirectory;
    this.clock = clock;
    this.expectedAudience = expectedAudience;
  }

  deriveIdentity({ productSession, clientIdentity = {} } = {}) {
    if (!productSession) {
      throw authenticationRequired();
    }
    if (productSession.revokedAt) {
      throw invalidAuthToken("The product auth token has been revoked.");
    }
    if (this.expectedAudience && productSession.audience !== this.expectedAudience) {
      throw invalidAuthToken("The product auth token has the wrong audience.");
    }

    let expiresAt;
    let tenantId;
    let userId;
    let authSubject;
    try {
      expiresAt = requireDate(productSession.expiresAt, "productSession.expiresAt");
      tenantId = requireNonEmptyString(productSession.tenantId, "productSession.tenantId");
      userId = requireNonEmptyString(productSession.userId, "productSession.userId");
      authSubject = requireNonEmptyString(productSession.authSubject, "productSession.authSubject");
    } catch {
      throw invalidAuthToken("The product auth token is malformed.");
    }

    if (expiresAt <= this.clock()) {
      throw invalidAuthToken("The product auth token has expired.");
    }

    const membershipSummary = this.tenantDirectory.summarizeMembership({ tenantId, userId });

    return Object.freeze({
      tenantId,
      userId,
      authSubject,
      requestId: productSession.requestId ?? null,
      correlationId: productSession.correlationId ?? null,
      expiresAt: toIso(expiresAt),
      membership: membershipSummary,
      ignoredClientIdentity: Object.freeze({
        tenantId: clientIdentity.tenantId ?? null,
        userId: clientIdentity.userId ?? null
      })
    });
  }

  assertSameTenant(identity, referenceTenantId) {
    requireIdentity(identity);
    requireNonEmptyString(referenceTenantId, "referenceTenantId");
    if (identity.tenantId !== referenceTenantId) {
      throw forbidden();
    }
    this.tenantDirectory.assertActiveMembership({
      tenantId: identity.tenantId,
      userId: identity.userId
    });
    return true;
  }

  assertSameTenantUser(identity, reference) {
    requireIdentity(identity);
    if (!reference) {
      throw forbidden();
    }
    const referenceTenantId = requireNonEmptyString(reference.tenantId, "reference.tenantId");
    const referenceUserId = requireNonEmptyString(reference.userId, "reference.userId");
    if (identity.tenantId !== referenceTenantId || identity.userId !== referenceUserId) {
      throw forbidden();
    }
    this.tenantDirectory.assertActiveMembership({
      tenantId: identity.tenantId,
      userId: identity.userId
    });
    return true;
  }
}

export function requireIdentity(identity) {
  if (!identity || !identity.tenantId || !identity.userId || !identity.authSubject) {
    throw authenticationRequired();
  }
}
