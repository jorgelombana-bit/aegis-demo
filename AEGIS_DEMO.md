# AEGIS Demo — Reference (endpoints, headers, bodies, responses)

> Master document describing, endpoint by endpoint, what **aegis-core** expects vs.
> what the **aegis-demo** UI sends. This file is the single source of truth; if
> a behavior in the UI does not match the aegis-core basecode, this file is
> wrong (or the code is).

All observations below come from reading the actual TypeScript source of
[`aegis/src/modules/...`](../../aegis/src/modules/) — not from marketing copy or
other `.md` files. File paths and line numbers are noted where useful.

---

## 0. Environment & base URLs

| Item | Value |
|---|---|
| aegis-core base URL (default) | `https://aegis-dev.preprodcxr.co` |
| Global URI prefix | `/api` |
| URI version | `/v1` (URI versioning) |
| CORS allow-list (aegis-core) | `http://localhost:4174, http://localhost:4200, …` — see `aegis/.env` (`CORS_ORIGINS`) |
| `AEGIS_PUBLIC_ORIGIN` (aegis-core) | Used by `buildDpopTargetUri` to validate `htu`. Must match the host the browser sees. For this demo it is `https://aegis-dev.preprodcxr.co`. |
| DPoP algorithms accepted | `ES256`, `RS256`, `PS256` (see `aegis/src/shared/utils/dpop-guard.validator.ts:19`) |
| `typ` required on DPoP proof | `dpop+jwt` |
| Rate limit default | 10 req / 60 s per tag (configurable via `envs.rateLimit.*`) |
| DPoP `jti` TTL (anti-replay) | 300 s (see `dpop-auth.guard.ts:178`) |
| DPoP `iat` max age | 300 s (see `dpop-guard.validator.ts:17`) |
| Internal API key (introspect) | `INTERNAL_API_KEY` env var on aegis-core; sent as `X-Internal-API-Key` |
| `X-Caller-Service` (introspect) | optional audit trace header, default `"internal-service"` |

The Vite dev server in this project proxies two path families:

| Browser path | Forwarded to | Inject? |
|---|---|---|
| `/api/*` | `{VITE_AEGIS_PROXY_TARGET}/api/*` | no |
| `/internal/*` | `{VITE_AEGIS_PROXY_TARGET}/api/v1/internal/*` (path rewritten) | `X-Internal-API-Key`, `X-Caller-Service` |

---

## 1. Endpoint inventory

| Tab in UI | HTTP method + path (aegis-core) | Auth pipeline |
|---|---|---|
| 1. Create User | `POST /api/v1/{country}/public/user` | `RateLimiterGuard` → `JweRegistrationDecryptInterceptor` → handler |
| 2. Login | `POST /api/v1/{country}/public/login` | `RateLimiterGuard` → `JweDecryptInterceptor` (no `UserCheck` validation) → `UserCheckGuard` → `AntiReplayGuard` → `DpopLoginGuard` → handler |
| 3. Logout | `POST /api/v1/{country}/public/logout` | `RateLimiterGuard` → `JweDecryptInterceptor` → `UserCheckGuard` → `AntiReplayGuard` → `DpopLoginGuard` → handler |
| 4. Introspect | `POST /api/v1/internal/token/introspect` | `InternalApiAuthGuard` (header `X-Internal-API-Key`) |
| 5. Security Test | Re-uses the above endpoints with 5 one-click scenarios. Each scenario renders a **Request Preview** card showing the URL, headers, DPoP proof (header + payload), JWE body (plaintext + encrypted), validations aegis-core runs, and expected response. | n/a |

The actual source files proving this:

- `aegis/src/modules/user/interface/http/user-http.controller.ts:104` — `registerPublicUser`
- `aegis/src/modules/auth/interface/https/public-login-http.controller.ts:87` — `publicHumanLogin`
- `aegis/src/modules/auth/interface/https/public-login-http.controller.ts:237` — `publicHumanLogout`
- `aegis/src/modules/auth/interface/https/introspect-token-http.controller.ts:39` — `introspect`

---

## 2. Common crypto

### 2.1 JWE encryption (every public endpoint)

aegis-core exposes its public encryption key at `GET /api/v1/auth/encryption-key`
(`aegis/src/modules/aegis-core/interface/http/auth-encryption-key.controller.ts:19`).
The JWK payload always has:

- `kty: "RSA"` (in dev) or `"EC"`
- `alg: "RSA-OAEP-256"` (or `"ECDH-ES+A256KW"`)
- `use: "enc"`, `kid: <sha256-base64url>`

The browser encrypts the inner payload with the imported public key:

- For `RSA-OAEP-256`: `jose.CompactEncrypt(...).setProtectedHeader({ alg, enc: 'A256GCM' }).encrypt(key)`
- The compact JWE string is the value of `secure_payload` in the outer body.

The list of `JWE_ALLOWED_*` algorithms is in
`aegis/src/shared/crypto/constants/crypto.constants.ts:75-78` — only `A256GCM`
content encryption is accepted.

### 2.2 DPoP proof (varies by endpoint)

The header has two valid forms depending on which guard is in front:

| Guard | Header name | Value | `ath` claim required? |
|---|---|---|---|
| `DpopLoginGuard` (login, logout) | `DPoP` | `DPoP <compact-jwt>` (with prefix) | no |
| `DpopAuthGuard` (/users/me, refresh) | `DPoP` | `<compact-jwt>` (raw, no prefix) | **yes** = `base64url(sha256(phantomAccessToken))` |

Both guards require the compact JWT to have:

- header: `typ: "dpop+jwt"`, `alg ∈ {ES256, RS256, PS256}`, `jwk: <public-key>`
- payload: `htm` matches HTTP method, `htu` matches full target URL (origin + path), `iat` within 300 s, `jti` (UUID v4)

In addition `DpopAuthGuard` enforces:

- `jkt` (computed from `jwk` in the header) equals the session's stored `dpop_jkt`
- `ath = base64url(sha256(Authorization: DPoP <access> -> <access>))`
- `jti` is unique within 300 s (Redis key `dpop:jti:<userId>:<jti>`)

Proof-construction in the demo lives in `frontend/src/lib/dpop.ts`; the
`actions.ts` orchestrator decides whether to:

- prepend `DPoP ` to the header value (login / logout), and
- include `ath` in the payload (only /users/me / refresh).

---

## 3. Endpoint-by-endpoint contract

### 3.1 `POST /api/v1/{country}/public/user` — Create User

Source: `user-http.controller.ts:104` + `user-self-service-registration.encrypted-request.dto.ts`
+ `user-self-service-registration-decrypted.dto.ts`.

**Request headers**: none required.

**Request body** (JSON, all required unless marked optional):

```json
{
  "user_identifier": "jorge.lombana@puntored.co",
  "device_context": {                       // optional
    "fingerprint": "sha256-...", 
    "ip": "127.0.0.1",
    "userAgent": "..."
  },
  "secure_payload": "<compact JWE, RSA-OAEP-256 / A256GCM>"
}
```

**Decrypted JWE payload** (must match `UserSelfServiceRegistrationDecryptedPayloadDto`):

```json
{
  "user_identifier": "jorge.lombana@puntored.co",
  "clientId": "a1b2c3d4-e5f6-4789-a012-000000000001",   // UUID; channel/client id from aegis-admin
  "userData": {
    "username": "jorge.lombana",
    "email": "jorge.lombana@puntored.co",
    "password": "..."
  },
  "credentials": { "user_check": "jorge.lombana@puntored.co" },  // must equal user_identifier
  "anti_replay": { "iat": 1700000000, "jti": "<UUID v4>" }
}
```

**Validation rules (server side)**:

- `user_identifier` must equal `credentials.user_check`.
- `clientId` must be a UUID.
- `userData.email` must be a valid email.
- `anti_replay.iat` is unix seconds, `jti` is UUID v4, `iat` within last 300 s.
- The JWE is decrypted by `JweRegistrationDecryptInterceptor` (`jwe-registration-decrypt.interceptor.ts`).

**Responses** (per `user.swagger.ts:209`):

| HTTP | Shape | When |
|---|---|---|
| 201 | `{ message: "Registration successful. Sign in with your credentials." }` | success |
| 400 | `{ error: "invalid_request", error_description: "..." }` (or ValidationPipe array) | bad country, JWE, DTO, aegis-admin validation |
| 401 | `{ error: "invalid_request", error_description: "Authentication request rejected" }` | JWE decryption failure or anti-replay rejection |
| 409 | `{ error: "already_exists", error_description: "Username or email is already in use" }` | user/email taken in Keycloak |
| 429 | `{ code: 1003, message: "Too many requests...", data: null }` | rate limit |
| 502 | `{ error: "invalid_request", error_description: "Service temporarily unavailable" }` | aegis-admin (gRPC) unavailable |

### 3.2 `POST /api/v1/{country}/public/login` — Phantom Token Login

Source: `public-login-http.controller.ts:87`.

**Request headers**:

| Name | Value |
|---|---|
| `DPoP` | `DPoP <jwt>` (with prefix; validated by `DpopLoginGuard`) |
| `Content-Type` | `application/json` (the outer envelope is JSON; the inner is JWE) |

**Request body** (JSON, all required):

```json
{
  "user_identifier": "jorge.lombana",
  "device_context": { "fingerprint": "...", "ip": "...", "userAgent": "..." },
  "secure_payload": "<compact JWE>"
}
```

**Decrypted JWE payload** (must match `PublicHumanLoginDecryptedPayloadDto`):

```json
{
  "user_identifier": "jorge.lombana",
  "credentials": {
    "clientId": "a1b2c3d4-...",      // UUID
    "pass": "...",
    "user_check": "jorge.lombana"    // must equal outer user_identifier
  },
  "anti_replay": { "iat": 1700000000, "jti": "<UUID v4>" }
}
```

**Validation chain** (`public-login-http.controller.ts:221-227`):
`UserCheckGuard` → `AntiReplayGuard` → `DpopLoginGuard`. Then the handler issues
the Phantom tokens.

**Responses**:

| HTTP | Shape |
|---|---|
| 200 | `{ access_token: "<UUID v4>", refresh_token: "<UUID v4>", expires_in: 300, token_type: "DPoP" }` |
| 400 | ValidationPipe array or `{ error, error_description }` |
| 401 | `{ error: "invalid_request", error_description: "Authentication request rejected" }` |
| 429 | rate limit |
| 502 | Keycloak unavailable |

### 3.3 `POST /api/v1/{country}/public/logout` — Phantom Token Logout

Source: `public-login-http.controller.ts:237` + `public-human-logout.handler.ts` + `public-human-logout.request.dto.ts`.

**Request headers**:

| Name | Value |
|---|---|
| `Authorization` | **`Bearer <phantom-access-uuid>`** (NOT `DPoP`. Validated by `extractBearerTokenFromRequest`.) |
| `DPoP` | **`<raw compact jwt>`** (NO `DPoP ` prefix; validated by `DpopAuthGuard` which is invoked manually inside the handler) |
| `Content-Type` | `application/json` |

> The `Authorization: Bearer` (not `DPoP`) is the single most common source of
> 401s on this endpoint. The phantom access UUID is the same opaque value
> returned by `/public/login`.

**Request body** — plain JSON, single field (validated by `PublicHumanLogoutRequestDto`):

```json
{
  "refresh_token": "550e8400-e29b-41d4-a716-446655440098"
}
```

> **No JWE envelope, no `user_identifier`, no `device_context`, no `anti_replay`.**
> Only the phantom refresh token returned by `/public/login`.

**DPoP proof** must include:

```json
{
  "htm": "POST",
  "htu": "https://aegis-dev.preprodcxr.co/api/v1/co/public/logout",
  "iat": 1700000000,
  "jti": "<UUID v4>",
  "ath": "base64url(sha256(<phantom_access_token>))"
}
```

The `jkt` is derived from the `jwk` in the header and validated against
`accessSession.dpop_jkt` from Redis.

**Server-side checks** (`public-human-logout.handler.ts:69-95`):
1. `DpopAuthGuard` validates the DPoP proof (typ, alg, jwk, htm, htu, iat, jti, ath, jkt).
2. `accessSession` and `refreshSession` both resolve from Redis.
3. `channelId` matches both sessions.
4. `sessionId` matches.
5. `refreshSession.accessTokenHash === sha256(phantomAccessToken)`.
6. `accessSession.dpopJkt === refreshSession.dpopJkt` (if both present).
7. **`accessSession.dpopJkt === dpopJkt`** — the DPoP key thumbprint from the proof must match the one stored at login. This is the **Phantom ↔ DPoP link check** for logout.
8. Revokes the upstream Keycloak refresh token and deletes the phantom sessions.

**Responses**:

| HTTP | Shape |
|---|---|
| 204 | empty body (`ThResponseBuilder.noContent(null)`) |
| 400 | validation errors (e.g. `refresh_token` missing) |
| 401 | `{ message: "DPOP authentication is required" }` or "Bearer phantom access token is required" or "Phantom session mismatch" |
| 429 | rate limit |
| 502 | Keycloak unavailable |

> The controller catches errors and **always returns 204** on the failure path
> (idempotent), but the trace log still surfaces the error. See
> `public-login-http.controller.ts:267-274`.

### 3.4 `POST /api/v1/internal/token/introspect` — Internal API

Source: `introspect-token-http.controller.ts:39`.

**Request headers**:

| Name | Value |
|---|---|
| `X-Internal-API-Key` | shared secret from aegis-core `INTERNAL_API_KEY` env var |
| `X-Caller-Service` (optional) | audit-trace identifier (default `"internal-service"`) |
| `Content-Type` | `application/json` |

**Request body** (JSON, all required):

```json
{ "token": "<UUID v4 of phantom access token>" }
```

> The DPoP proof is **not** required for introspection (no DPoP guard here).

**Responses** (RFC 7662-style):

| HTTP | Shape |
|---|---|
| 200 | `{ active: true, sub, country, client_id, roles, dpop_jkt, iat, exp }` |
| 200 | `{ active: false }` — invalid/expired/missing session (returned even for "not found") |
| 400 | validation error |
| 401 | missing/invalid `X-Internal-API-Key` |

### 3.5 `GET /api/v1/users/me` — Phantom-protected resource

Source: `user-http.controller.ts:149`.

**Request headers**:

| Name | Value |
|---|---|
| `Authorization` | **`DPoP <phantom-access-uuid>`** (NOT `Bearer`; the `PhantomTokenGuard` requires the `DPoP ` prefix) |
| `DPoP` | **`<jwt>`** (raw, no prefix; validated by `DpopAuthGuard`) |

**DPoP proof** must include:

```json
{
  "htm": "GET",
  "htu": "https://aegis-dev.preprodcxr.co/api/v1/users/me",
  "iat": 1700000000,
  "jti": "<UUID v4>",
  "ath": "base64url(sha256(<phantomAccessToken>))"
}
```

**Responses**:

| HTTP | Shape |
|---|---|
| 200 | `{ code: 200, message: "success", data: { userId, sessionId, username, email?, country, roles, clientId, channelId } }` |
| 401 | `{ message: "Unauthorized", statusCode: 401 }` |
| 429 | rate limit |

### 3.6 `POST /api/v1/auth/refresh-token` — Phantom Token refresh

Source: `phantom-token-refresh-http.controller.ts:37`.

**Request headers**:

| Name | Value |
|---|---|
| `Authorization` | `DPoP <phantom-access-uuid>` |
| `DPoP` | `<jwt>` (raw) |
| `Content-Type` | **`application/json`** (no JWE) |

**Request body** (JSON, all required):

```json
{
  "refresh_token": "<UUID v4>",
  "client_id": "<UUID v4 channel id>"
}
```

**DPoP proof** must include `ath` (same as `/users/me`).

**Responses**: same shape as login.

---

## 4. Phantom ↔ DPoP link — where it's enforced

| Endpoint | Link check |
|---|---|
| `POST /public/login` | None (DPoP is bound to the new session by `request.dpopJkt = jkt`). |
| `POST /public/logout` | `accessSession.dpopJkt === dpopJkt` (handler line 92-94). |
| `POST /auth/refresh-token` | `verifyDpopJktMatchesSession` in `DpopAuthGuard`. |
| `GET /users/me` | `verifyDpopJktMatchesSession` in `DpopAuthGuard`. |
| `POST /internal/token/introspect` | n/a (no DPoP). Returns `dpop_jkt` claim in the response. |

The DPoP link is therefore verifiable from outside via:
1. Login (capture `access_token` + the `jkt` printed in the trace).
2. Introspect (response includes `dpop_jkt`).
3. Compare.

If the values match, the link is valid. The Security Test view automates this
check and exposes dedicated failure scenarios.

---

## 5. Validation cases (Security Test scenarios)

The Security Test tab renders one card per scenario. Each card shows the **full request** that will be sent (URL, method, headers, DPoP proof structure, JWE body) and the **expected response**.

| # | Card | Task case | Endpoint | Expected |
|---|---|---|---|---|
| 1 | Login válido (Phantom + DPoP correctos) | Caso 1 (parcial) | `POST /api/v1/{country}/public/login` | 200 + phantom tokens |
| 2 | Login con DPoP alterado (htu falsificado) | Caso 3 | `POST /api/v1/{country}/public/login` | 401 `DPOP_HTU_MISMATCH` |
| 3 | Logout con DPoP inválido (jkt distinto) | Caso 5 | `POST /api/v1/{country}/public/logout` | 401 Phantom session mismatch |
| 4 | Introspect con token inválido (UUID sin sesión) | Caso 6 | `POST /internal/token/introspect` | 200 `{ active: false }` |
| 5 | Introspect con token expirado | Caso 4 (variante) | `POST /internal/token/introspect` | 200 `{ active: false }` (Redis TTL expiró) |

> Caso 2 (Phantom + DPoP diferente sobre endpoint protegido) se verifica ejecutando
> el botón 1 (login válido) y luego la pestaña 5 con un DPoP keypair fresco; la
> respuesta debe ser 401 `DPOP_JKT_MISMATCH`. Documentado en el footer de la tab.

---

## 6. Mapping UI → aegis-core (debugging cheatsheet)

| UI action | Internal flow |
|---|---|
| Click "Create User" | `actions.actionCreateUser` → `encryptJwe` (JWE) → `api.createUser` → `POST /api/v1/{country}/public/user` |
| Click "Login" | `actions.actionLogin` → `encryptJwe` → `dpop.buildDpopProof` (no `ath`) → `api.login` (header `DPoP: DPoP <jwt>`) |
| Click "Logout" | `actions.actionLogout` → `encryptJwe` → `dpop.buildDpopProof` (no `ath`) → `api.logout` (header `Authorization: Bearer <access>`, `DPoP: DPoP <jwt>`) |
| Click "Introspect" | `actions.actionIntrospect` → `api.introspect` → `POST /internal/token/introspect` (proxied) |
| Click "/users/me" | `actions.actionGetMe` → `dpop.buildDpopProof` (with `ath`) → `api.getMe` (header `Authorization: DPoP <access>`, `DPoP: <jwt>`) |
| Click "Refresh" | `actions.actionRefresh` → `dpop.buildDpopProof` (with `ath`) → `api.refresh` (header `Authorization: DPoP <access>`, `DPoP: <jwt>`, body JSON) |

The Vite dev server terminal logs `[aegis-proxy] →/←` lines for every hop, so
open the terminal where you ran `pnpm dev` to verify the forwarding.
