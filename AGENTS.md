# AGENTS.md

## Repo Purpose

`ai-assist-auth-service` owns product authentication, server-derived `tenantId` and `userId`, tenant membership checks, Google OAuth lifecycle metadata, and authZ helper behavior.

## Agent Instructions

- Read `README.md`, `ai-assist-platform-context.md`, and `../ai-assist-architecture/lld-auth-secrets-tenancy.md` before changing behavior.
- Derive identity from verified server-side auth context. Never trust client-supplied `tenantId` or `userId`.
- Treat `sessionId`, `resourceId`, `actionId`, and grant IDs as references requiring authorization.
- OAuth token material must remain encrypted behind injected boundaries. APIs and tests should return metadata only.
- Do not leak whether another tenant's resource exists.
- Keep Google OAuth handling separate from provider API key handling; provider keys belong to `ai-assist-secrets-service`.
- Add tests for authN failures, authZ failures, disabled tenants/users, cross-tenant references, OAuth revocation, and metadata-only responses.

## Commands

- Run tests with `node --test`.
- `npm` may not be available in this environment; prefer the direct Node command.

## Review Notes

Before committing, review for tenant isolation, secret/token exposure, typed error categories, and whether downstream calls are skipped after auth failures.
