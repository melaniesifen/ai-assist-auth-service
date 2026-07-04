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
- [x] `AUTH-002` / M8-T2: Verify product-session validation semantics for HTTP/SSE-facing boundaries through server-derived identity, audience, expiry, revoked-token, malformed-token, active-membership, and reference-authorization tests.
- [x] `AUTH-002` / M8-T2: Define token expiry and refresh behavior for backend command APIs and SSE endpoints through injected Google token refresh and reconnect-required outcomes.
- [x] `AUTH-002`: Return distinct typed errors for unauthorized, expired, and malformed product credentials.
- [x] `AUTH-002` / M3: Expose server-derived first-run product session status for authenticated, anonymous, expired, malformed, and unauthorized sessions.
- [x] `AUTH-003` / M3: Expose Google OAuth setup status for disconnected, connected, and reconnect-required states using metadata-only responses.
- [x] `AUTH-002` / M8-T2: Add deterministic boundary tests for product session validation on HTTP/SSE-style setup, command, stream, review, and apply references.
- [x] `AUTH-003` / M8-T2: Add Google OAuth start flow with signed state, nonce, tenant/user binding, redirect target validation, least-privilege scopes, and expiration.
- [x] `AUTH-003` / M8-T2: Add Google OAuth callback flow with state validation, single-use nonce consumption, injected code exchange, encrypted token storage, metadata-only response, and safe audit events.
- [x] `AUTH-003` / M8-T2: Add Google OAuth refresh flow that marks invalid-grant or failed refresh outcomes revoked and reconnect-required.
- [x] `AUTH-003` / M8-T2: Add deterministic tests for OAuth start, callback, replay, wrong user, expired state, exchange failure, refresh failure, revoke, disconnect, and reconnect-required paths.
- [x] `AUTH-003`: Add KMS-backed OAuth token protector adapter.
- [x] `AUTH-003`: Add DynamoDB OAuth token repository adapter.
- [x] `AUTH-006` / M8-T2: Document and enforce auth-service token decrypt boundaries through injected token-protector context and metadata-only public/API responses.
- [x] `AUTH-006` / M8-T2: Add failure-mode validation for token-protector deny/decrypt failures, expired state, invalid nonce/replay, and revoked Google tokens without requiring cloud KMS.
- [x] `EVT-001`: Add HTTP route handlers and request/response contract tests for auth and OAuth commands.
- [x] `OPS-001`: Ensure auth and OAuth endpoints are covered by MVP edge rate-limit configuration.
- [x] `OPS-003` / M8-T2: Add metadata-only audit emission for Google OAuth start, connect, and denied callback states.
- [x] `OPS-003` / M3: Verify auth setup status responses exclude OAuth token material and ciphertext.
- [x] `AUTH-002` / M9-T3: Verify deploy-shaped HTTP and SSE product-session authorization derives identity server-side and rejects cross-tenant session/action references.
- [x] `AUTH-003` / M9-T3: Verify deployed Google OAuth callback config, signed state, replay rejection, wrong-user rejection, encrypted token storage, refresh failure, revoked token, disconnect, and metadata-only status using injected fakes.
- [x] `AUTH-003` / M9-T3: Add deploy-shaped runtime config validation for generic callback URL, API/SSE/web endpoints, allowed origins, trusted-user mode, and Google OAuth client ID.
- [x] `OPS-003` / M9-T3: Verify runtime metadata, OAuth audit events, setup status, and handoff responses exclude OAuth tokens, authorization codes, authorization headers, bearer values, and ciphertext.
- [x] `AUTH-002` / M9-T9: Add canonical deployed auth HTTP handlers for trusted-user login, logout, session status, server-derived tenant/user identity, expired or revoked session status, and metadata-only errors.
- [x] `AUTH-003` / M9-T9: Add canonical Google OAuth HTTP handlers for start, callback, status, and disconnect with signed-state replay rejection, tenant/user binding, deployed callback URL validation, and metadata-only responses.
- [x] `AUTH-003` / M9-T9: Add deploy adapters for Google token exchange/refresh, Secrets Manager OAuth client secret loading, KMS token encryption/decryption, and DynamoDB OAuth token persistence.
- [x] M11-T2: Implement multi-user trusted dev session issuance from an
  allowed-user source that maps verified `authSubject` values to distinct
  server-derived `tenantId`, `userId`, role, and active status.
- [x] M11-T2: Reject non-allowed, disabled, or inactive users before product
  session creation; treat WAF/IP allowlisting as edge access control only.
- [x] M11-T2: Add user A/user B tests proving OAuth start, callback, status,
  disconnect, token refresh, and token handoff are scoped to the authenticated
  user's derived tenant/user identity.

## Quality And Production Tasks

- [x] Raise line coverage to at least 95%.
- [ ] Add tenant admin and membership lifecycle support.
- [ ] Add deployment health checks and operational metrics.
- [ ] Add deployment-style pipeline tasks for auth route smoke tests, migration checks, IAM policy validation, and rollback notes.
