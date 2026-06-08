# Task Breakdown

Update this file as implementation progresses. Check off completed tasks in the same change that implements or verifies them.

Sources:

- `../ai-assist-architecture/implementation-task-breakdown.md`
- `../ai-assist-architecture/lld-auth-secrets-tenancy.md`

## Completed Bootstrap

- [x] Initially bootstrap dependency-light ESM auth domain logic; superseded by the completed Python migration in `REPO-002`.
- [x] `AUTH-001`: Implement server-derived identity helpers that ignore client-supplied `tenantId` and `userId`.
- [x] `AUTH-001`: Implement tenant, user, and active membership checks.
- [x] `AUTH-001`: Reject disabled tenants, disabled users, inactive memberships, and cross-tenant references before downstream access.
- [x] `AUTH-001`: Return typed authorization errors for cross-tenant and inactive-member access.
- [x] `AUTH-002`: Reject missing, expired, and malformed product session claims at the domain boundary.
- [x] `AUTH-003`: Implement Google OAuth token metadata lifecycle with injected encryption boundary.
- [x] `AUTH-003`: Keep OAuth token public responses metadata-only.
- [x] `AUTH-003`: Return reconnect-required errors for expired non-refreshable and revoked Google OAuth tokens.
- [x] `AUTH-003` / M4: Expose internal Google Docs list/read token handoff with status, expiry, scope metadata, and no ciphertext.
- [x] `AUTH-003` / M4: Return reconnect-required handoff metadata for unavailable, revoked, expired, and insufficient-scope Google tokens.
- [x] `AUTH-003` / M4: Verify public Google OAuth status/setup responses remain metadata-only with no token, authorization-code, authorization-header, or ciphertext fields.
- [x] `AUTH-003` / M4: Write fresh review feedback for the auth token handoff diff.
- [x] `AUTH-003` / M7-T4: Expose metadata-only Google token handoff status for apply validation and require reconnect-required results for unavailable, expired, revoked, and insufficient-scope Google tokens.
- [x] `AUTH-001` / M7-T4: Verify apply-facing session, resource, and action references use server-derived identity and reject missing auth, expired, revoked, malformed, wrong-audience, disabled-user, and cross-tenant references.
- [x] `AUTH-003` / M7-T4: Verify apply validation status responses do not expose OAuth tokens, authorization codes, authorization headers, ciphertext, or raw document/action payload content.
- [x] Initially add unit tests using `node:test`; superseded by equivalent Python `unittest` coverage in `REPO-002`.
- [x] Document current Python test and syntax-check commands in `README.md`.
- [x] Ignore local prompts, feedback, coverage output, dependencies, and build artifacts.

## Pending Architecture Tasks

- [ ] `REPO-001`: Decide final package structure, language, framework, package manager, and production module layout for this repo.
- [x] `REPO-002`: Migrate the auth service from the JavaScript ESM bootstrap to Python while preserving or intentionally superseding current auth, tenancy, and OAuth behavior.
- [x] `REPO-002`: Port or replace existing `node:test` coverage with equivalent Python tests and document the Python package layout and local test commands.
- [x] Migration gate: Do not continue broad new auth-service feature work until the Python migration is completed or explicitly deferred.
- [x] `AUTH-001`: Add authorization helpers for client-supplied `sessionId`, `resourceId`, `actionId`, and grant IDs as references.
- [ ] `AUTH-002`: Add product session or JWT validation adapter.
- [ ] `AUTH-002`: Define token expiry and refresh behavior for backend command APIs and SSE endpoints.
- [x] `AUTH-002`: Return distinct typed errors for unauthorized, expired, and malformed product credentials.
- [x] `AUTH-002` / M3: Expose server-derived first-run product session status for authenticated, anonymous, expired, malformed, and unauthorized sessions.
- [x] `AUTH-003` / M3: Expose Google OAuth setup status for disconnected, connected, and reconnect-required states using metadata-only responses.
- [ ] `AUTH-002`: Add integration tests for product session validation on HTTP command APIs and SSE stream creation.
- [ ] `AUTH-003`: Add Google OAuth start flow with signed state, nonce, identity binding, redirect target, and expiration.
- [ ] `AUTH-003`: Add Google OAuth callback flow with state validation and token exchange.
- [ ] `AUTH-003`: Add Google OAuth refresh flow that marks invalid-grant refresh failures revoked.
- [ ] `AUTH-003`: Add integration tests for OAuth start, callback, refresh, revoke, and reconnect-required paths.
- [ ] `AUTH-003`: Add KMS-backed OAuth token protector adapter.
- [ ] `AUTH-003`: Add DynamoDB OAuth token repository adapter.
- [ ] `AUTH-006`: Document and enforce auth-service IAM boundaries for Google OAuth token decrypt paths.
- [ ] `AUTH-006`: Add failure-mode validation for KMS deny/decrypt failures, expired state, invalid nonce, and revoked Google tokens.
- [ ] `EVT-001`: Add HTTP route handlers and request/response contract tests for auth and OAuth commands.
- [ ] `OPS-001`: Ensure auth and OAuth endpoints are covered by MVP edge rate-limit configuration.
- [ ] `OPS-003`: Add metadata-only audit and log emission for login, OAuth connect, OAuth revoke, and denied access.
- [x] `OPS-003` / M3: Verify auth setup status responses exclude OAuth token material and ciphertext.

## Quality And Production Tasks

- [x] Raise line coverage to at least 95%.
- [ ] Add tenant admin and membership lifecycle support.
- [ ] Add deployment health checks and operational metrics.
- [ ] Add deployment-style pipeline tasks for auth route smoke tests, migration checks, IAM policy validation, and rollback notes.
