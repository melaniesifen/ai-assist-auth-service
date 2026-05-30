# ai-assist-auth-service

Domain-layer bootstrap for product identity, tenant membership, and Google OAuth token metadata.

This repo intentionally has no runtime dependencies and no AWS or Google network integration yet. The current code is built for deterministic `node:test` coverage and future adapters.

## Current Boundary

The service owns:

- Server-derived `tenantId`, `userId`, and `authSubject` from a trusted product session.
- Tenant, user, and membership checks.
- Typed authentication and authorization errors.
- Google OAuth token metadata lifecycle.
- Coordination with an injected token protector for encryption.

The service does not own:

- Provider API keys.
- Model provider calls.
- Google Docs API calls.
- Prompt construction.
- HTTP routing.
- KMS, DynamoDB, or real OAuth exchange calls.

## Domain Modules

- `src/errors.js`: typed `AuthError` values with stable error codes and HTTP status.
- `src/tenancy.js`: in-memory tenant, user, and membership repository with active-member authorization checks.
- `src/identity.js`: product session identity derivation that ignores client-supplied identity fields.
- `src/oauthTokens.js`: Google OAuth token metadata lifecycle using injected encryption.
- `src/index.js`: public exports.

## Security Invariants

- Client-supplied `tenantId` and `userId` are ignored for identity.
- Tenant membership is checked before token access.
- OAuth token responses are metadata only.
- Raw OAuth tokens and ciphertext are not returned by public service methods.
- Encryption context includes `tenantId`, `userId`, `provider`, and `purpose=oauth-token`.

## Future Adapters

Planned AWS and Google integrations should wrap the existing domain contracts:

- Product session or JWT validation adapter.
- OAuth state signing and Google token exchange adapter.
- KMS token protector implementing `encrypt(plaintext, { context })`.
- DynamoDB token repository implementing the same repository shape as `InMemoryOAuthTokenRepository`.
- HTTP handlers for `/auth/session`, `/oauth/google/start`, `/oauth/google/callback`, `/oauth/google/status`, and `/oauth/google/connection`.

Run tests:

```sh
npm test
```
