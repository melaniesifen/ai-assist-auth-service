import {
  AUTH_ERROR_CODES,
  AuthError,
  forbidden,
  validationFailed
} from "./errors.js";
import { cloneDate, requireNonEmptyString, toIso } from "./validation.js";

export const TENANT_STATUS = Object.freeze({
  ACTIVE: "active",
  DISABLED: "disabled"
});

export const USER_STATUS = Object.freeze({
  ACTIVE: "active",
  DISABLED: "disabled"
});

export const MEMBERSHIP_STATUS = Object.freeze({
  ACTIVE: "active",
  DISABLED: "disabled"
});

export const TENANT_ROLES = Object.freeze({
  OWNER: "owner",
  MEMBER: "member"
});

const ALLOWED_ROLES = new Set(Object.values(TENANT_ROLES));

export class InMemoryTenantDirectory {
  constructor() {
    this.tenants = new Map();
    this.users = new Map();
    this.memberships = new Map();
  }

  putTenant({ tenantId, status = TENANT_STATUS.ACTIVE, createdAt = new Date() }) {
    requireNonEmptyString(tenantId, "tenantId");
    this.tenants.set(tenantId, {
      tenantId,
      status,
      createdAt: cloneDate(createdAt)
    });
    return this.getTenant(tenantId);
  }

  putUser({ userId, status = USER_STATUS.ACTIVE, defaultTenantId = null, createdAt = new Date() }) {
    requireNonEmptyString(userId, "userId");
    this.users.set(userId, {
      userId,
      status,
      defaultTenantId,
      createdAt: cloneDate(createdAt)
    });
    return this.getUser(userId);
  }

  putMembership({
    tenantId,
    userId,
    role = TENANT_ROLES.MEMBER,
    status = MEMBERSHIP_STATUS.ACTIVE,
    createdAt = new Date(),
    disabledAt = null
  }) {
    requireNonEmptyString(tenantId, "tenantId");
    requireNonEmptyString(userId, "userId");
    if (!ALLOWED_ROLES.has(role)) {
      throw validationFailed("role", "Tenant role is not supported.");
    }
    const membership = {
      tenantId,
      userId,
      role,
      status,
      createdAt: cloneDate(createdAt),
      disabledAt: cloneDate(disabledAt)
    };
    this.memberships.set(membershipKey(tenantId, userId), membership);
    return this.getMembership(tenantId, userId);
  }

  getTenant(tenantId) {
    const tenant = this.tenants.get(tenantId);
    return tenant ? { ...tenant, createdAt: cloneDate(tenant.createdAt) } : null;
  }

  getUser(userId) {
    const user = this.users.get(userId);
    return user ? { ...user, createdAt: cloneDate(user.createdAt) } : null;
  }

  getMembership(tenantId, userId) {
    const membership = this.memberships.get(membershipKey(tenantId, userId));
    return membership
      ? {
          ...membership,
          createdAt: cloneDate(membership.createdAt),
          disabledAt: cloneDate(membership.disabledAt)
        }
      : null;
  }

  assertActiveMembership({ tenantId, userId }) {
    requireNonEmptyString(tenantId, "tenantId");
    requireNonEmptyString(userId, "userId");

    const tenant = this.tenants.get(tenantId);
    if (!tenant || tenant.status !== TENANT_STATUS.ACTIVE) {
      throw new AuthError({
        code: AUTH_ERROR_CODES.TENANT_DISABLED,
        message: "Tenant is disabled or unavailable.",
        status: 403
      });
    }

    const user = this.users.get(userId);
    if (!user || user.status !== USER_STATUS.ACTIVE) {
      throw new AuthError({
        code: AUTH_ERROR_CODES.USER_DISABLED,
        message: "User is disabled or unavailable.",
        status: 403
      });
    }

    const membership = this.memberships.get(membershipKey(tenantId, userId));
    if (!membership || membership.status !== MEMBERSHIP_STATUS.ACTIVE) {
      throw forbidden();
    }

    return {
      tenant: { ...tenant, createdAt: cloneDate(tenant.createdAt) },
      user: { ...user, createdAt: cloneDate(user.createdAt) },
      membership: {
        ...membership,
        createdAt: cloneDate(membership.createdAt),
        disabledAt: cloneDate(membership.disabledAt)
      }
    };
  }

  summarizeMembership({ tenantId, userId }) {
    const { membership } = this.assertActiveMembership({ tenantId, userId });
    return {
      tenantId,
      userId,
      role: membership.role,
      status: membership.status,
      createdAt: toIso(membership.createdAt),
      disabledAt: toIso(membership.disabledAt)
    };
  }
}

function membershipKey(tenantId, userId) {
  return `${tenantId}:${userId}`;
}
