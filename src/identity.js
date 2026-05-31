import {
  authenticationRequired,
  expiredAuthToken,
  forbidden,
  invalidAuthToken,
  malformedAuthToken,
  validationFailed
} from "./errors.js";
import { requireDate, requireNonEmptyString, toIso } from "./validation.js";

export const AUTH_REFERENCE_TYPES = Object.freeze({
  SESSION: "session",
  RESOURCE: "resource",
  ACTION: "action",
  GRANT: "grant"
});

const REFERENCE_ID_FIELDS = Object.freeze({
  [AUTH_REFERENCE_TYPES.SESSION]: "sessionId",
  [AUTH_REFERENCE_TYPES.RESOURCE]: "resourceId",
  [AUTH_REFERENCE_TYPES.ACTION]: "actionId",
  [AUTH_REFERENCE_TYPES.GRANT]: "grantId"
});

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
      throw malformedAuthToken();
    }

    if (expiresAt <= this.clock()) {
      throw expiredAuthToken();
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

  assertAuthorizedReference(identity, reference, { referenceType } = {}) {
    requireIdentity(identity);
    const idField = REFERENCE_ID_FIELDS[referenceType];
    if (!idField) {
      throw validationFailed("referenceType", "Reference type is not supported.");
    }
    if (!reference) {
      throw forbidden();
    }

    let referenceId;
    let referenceTenantId;
    let referenceUserId;
    try {
      referenceId = requireNonEmptyString(reference[idField], `reference.${idField}`);
      referenceTenantId = requireNonEmptyString(reference.tenantId, "reference.tenantId");
      referenceUserId = requireNonEmptyString(reference.userId, "reference.userId");
    } catch {
      throw forbidden();
    }
    if (identity.tenantId !== referenceTenantId || identity.userId !== referenceUserId) {
      throw forbidden();
    }
    this.tenantDirectory.assertActiveMembership({
      tenantId: identity.tenantId,
      userId: identity.userId
    });
    return Object.freeze({
      referenceType,
      referenceId,
      tenantId: referenceTenantId,
      userId: referenceUserId
    });
  }
}

export function requireIdentity(identity) {
  if (!identity || !identity.tenantId || !identity.userId || !identity.authSubject) {
    throw authenticationRequired();
  }
}
