# ai-assist-auth-service

Python domain layer for product identity, tenant membership, and Google OAuth token metadata.

This repo intentionally has no runtime dependencies and no AWS or Google network integration yet. The current code uses only the Python standard library for deterministic `unittest` coverage and future adapters.

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

- `src/ai_assist_auth_service/errors.py`: typed `AuthError` values with stable error codes and HTTP status.
- `src/ai_assist_auth_service/tenancy.py`: in-memory tenant, user, and membership repository with active-member authorization checks.
- `src/ai_assist_auth_service/identity.py`: product session identity derivation that ignores client-supplied identity fields.
- `src/ai_assist_auth_service/oauth_tokens.py`: Google OAuth token metadata lifecycle and internal Google Docs token handoff using injected encryption.
- `src/ai_assist_auth_service/__init__.py`: public exports.

## Security Invariants

- Client-supplied `tenantId` and `userId` are ignored for identity.
- Tenant membership is checked before token access.
- OAuth token responses are metadata only.
- Raw OAuth tokens and ciphertext are not returned by public service methods.
- Internal Google Docs token handoff returns an access token only through the injected token-protector boundary after tenant membership, token status, expiry, and required-scope checks.
- Encryption context includes `tenantId`, `userId`, `provider`, and `purpose=oauth-token`.

## Future Adapters

Planned AWS and Google integrations should wrap the existing domain contracts:

- Product session or JWT validation adapter.
- OAuth state signing and Google token exchange adapter.
- KMS token protector implementing `encrypt(plaintext, { context })`.
- DynamoDB token repository implementing the same repository shape as `InMemoryOAuthTokenRepository`.
- HTTP handlers for `/auth/session`, `/oauth/google/start`, `/oauth/google/callback`, `/oauth/google/status`, and `/oauth/google/connection`.

## Task Breakdown

Implementation tasks are tracked in [TASKS.md](TASKS.md). Update the checkboxes there in the same change that implements or verifies a task.

## Local Python Layout

- Runtime: Python, standard library only.
- Package source: `src/ai_assist_auth_service/`.
- Tests: `tests/`.
- Metadata: `pyproject.toml`.

No virtual environment is required for the current stdlib-only tests. If future work adds third-party dependencies, declare them in repo-local tooling files before relying on them.

## Testing

Run the unit tests with:

```sh
python3 -m unittest discover -s tests
```

Run a stdlib syntax/import check with:

```sh
python3 -m compileall -q src tests
```

Coverage tooling is not configured because the migration is dependency-free. If later tooling writes virtualenv, cache, coverage, test-report, dependency, or build output, those generated paths are ignored by `.gitignore`.
