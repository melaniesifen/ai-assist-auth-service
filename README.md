# ai-assist-auth-service

Python service for product identity, tenant membership, Google OAuth, and OAuth
token persistence.

The domain code remains dependency-light and deterministic for unit tests. The
deployed runtime includes a small HTTP adapter plus lazy AWS/Google adapters for
KMS, DynamoDB, Secrets Manager, and Google OAuth token exchange.

## Current Boundary

The service owns:

- Server-derived `tenantId`, `userId`, and `authSubject` from a trusted product session.
- Tenant, user, and membership checks.
- Typed authentication and authorization errors.
- Google OAuth token metadata lifecycle.
- Coordination with an injected token protector for encryption.
- Canonical HTTP handlers for `/auth/session`, `/oauth/google/start`,
  `/oauth/google/callback`, `/oauth/google/status`, and
  `/oauth/google/connection`.
- Trusted-user bootstrap login/logout when the deployment explicitly configures
  trusted-user bootstrap and product-session signing secrets.
- KMS-backed OAuth token encryption and DynamoDB token persistence through
  adapters that match the injected domain repository/protector contracts.

The service does not own:

- Provider API keys.
- Model provider calls.
- Google Docs API calls.
- Prompt construction.
- API Gateway edge auth.
- Google Docs API calls.

## Domain Modules

- `src/ai_assist_auth_service/errors.py`: typed `AuthError` values with stable error codes and HTTP status.
- `src/ai_assist_auth_service/tenancy.py`: in-memory tenant, user, and membership repository with active-member authorization checks.
- `src/ai_assist_auth_service/identity.py`: product session identity derivation that ignores client-supplied identity fields.
- `src/ai_assist_auth_service/oauth_tokens.py`: Google OAuth token metadata lifecycle and internal Google Docs token handoff using injected encryption.
- `src/ai_assist_auth_service/oauth_flow.py`: signed Google OAuth state, start/callback orchestration, replay protection, redirect validation, and injected code exchange.
- `src/ai_assist_auth_service/http_app.py`: canonical auth/OAuth HTTP route
  handlers for deployed service containers.
- `src/ai_assist_auth_service/product_session.py`: server-signed trusted-user
  product-session issuing, verification, and process-local logout revocation.
- `src/ai_assist_auth_service/aws_adapters.py`: KMS token protector, DynamoDB
  OAuth token repository, and Secrets Manager secret resolver.
- `src/ai_assist_auth_service/google_oauth_adapter.py`: Google OAuth
  code-exchange and refresh adapter.
- `src/ai_assist_auth_service/runtime.py`: deploy-shaped runtime config validation and HTTP/SSE route authorization helpers with injected services.
- `src/ai_assist_auth_service/__init__.py`: public exports.

## Security Invariants

- Client-supplied `tenantId` and `userId` are ignored for identity.
- Tenant membership is checked before token access.
- OAuth token responses are metadata only.
- Google OAuth start/callback uses signed state with nonce replay protection and tenant/user binding.
- Deploy-shaped runtime config requires the Google OAuth callback URL to match the configured API callback route.
- HTTP and SSE route helpers derive identity from the product session and authorize client-supplied references before downstream use.
- Raw OAuth tokens and ciphertext are not returned by public service methods.
- Internal Google Docs token handoff returns an access token only through the injected token-protector boundary after tenant membership, token status, expiry, and required-scope checks.
- Encryption context includes `tenantId`, `userId`, `provider`, and `purpose=oauth-token`.

## Deployed Runtime Config

The deployed auth service expects the generic M9 runtime keys plus:

- `PRODUCT_AUTH_AUDIENCE`
- `PRODUCT_AUTH_HMAC_SECRET`
- `PRODUCT_SESSION_TTL_HOURS`
- `OAUTH_STATE_SIGNING_SECRET`
- `TRUSTED_USER_TENANT_ID`
- `TRUSTED_USER_USER_ID`
- `TRUSTED_USER_AUTH_SUBJECT`
- `TRUSTED_USER_BOOTSTRAP_SECRET`
- `GOOGLE_OAUTH_CLIENT_SECRET_REF`
- `APP_KMS_KEY_ID`
- `OAUTH_TOKEN_TABLE_NAME`

Secret values must come from deployment-time secret management or ignored local
configuration. Do not commit plaintext secrets. OAuth client secret refs point
to Secrets Manager; token ciphertext is stored in DynamoDB and encrypted with
the shared app KMS key.

## Task Breakdown

Implementation tasks are tracked in [TASKS.md](TASKS.md). Update the checkboxes there in the same change that implements or verifies a task.

## Local Python Layout

- Runtime: Python, standard library only.
- Package source: `src/ai_assist_auth_service/`.
- Tests: `tests/`.
- Metadata: `pyproject.toml`.

No virtual environment is required for the current unit tests because AWS and
Google adapters are lazy. The deployed container installs repo-local
dependencies from `pyproject.toml`.

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
