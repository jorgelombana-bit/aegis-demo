# aegis-demo

> **Renombrado**: este proyecto antes vivía en `utils-mixed/temp-login/frontend/`.
> Ahora es `AEGIS-DEMO/` y se llama `aegis-demo` (ver `package.json`).

Single-page React app that exercises the security flows of **Aegis Core** end-to-end:

- Self-service user registration (`POST /api/v1/{country}/public/user`)
- Phantom Token login with DPoP proof + Anti-replay + Rate Limit
  (`POST /api/v1/{country}/public/login`, header `DPoP: DPoP <jwt>`)
- Phantom Token logout with DPoP proof + `Authorization: Bearer <access>`
  (`POST /api/v1/{country}/public/logout`)
- Token introspection protected by the Internal API Guard
  (`POST /api/v1/internal/token/introspect`)
- Validation of the Phantom ↔ DPoP link through the protected `GET /api/v1/users/me`
  (`Authorization: DPoP <access>`, DPoP proof with `ath`)
- Phantom Token rotation via the refresh endpoint
  (`POST /api/v1/auth/refresh-token`)
- A "Security Test" mode with one-click failure scenarios (altered DPoP, mismatched
  jkt, invalid phantom tokens, expired tokens, etc.)

The UI talks **directly** to Aegis Core through the Vite dev-server proxy, with no
backend of its own. All crypto (JWE + DPoP) runs in the browser using
[`jose`](https://github.com/panva/jose) and the WebCrypto API.

> El contrato exacto de cada endpoint, header y body está documentado en
> [`AEGIS_DEMO.md`](./AEGIS_DEMO.md), derivado directamente de la basecode de
> aegis-core.

## Quick start

```bash
pnpm install
cp .env.example .env
# Edit .env and set VITE_AEGIS_INTERNAL_API_KEY to the real value from aegis-core.
pnpm dev
# open http://localhost:5173
```

Build for production:

```bash
pnpm build
pnpm preview
```

## Environment variables

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `VITE_AEGIS_PROXY_TARGET` | `https://aegis-dev.preprodcxr.co` | No | Where the dev server proxies `/api` and `/internal` to. |
| `VITE_AEGIS_PUBLIC_ORIGIN` | `https://aegis-dev.preprodcxr.co` | No | Public origin used to build the DPoP `htu` claim. |
| `VITE_AEGIS_INTERNAL_API_KEY` | _empty_ | Yes (for introspect) | Server-side only; injected by Vite as `X-Internal-API-Key`. Never bundled into the client. |
| `VITE_DEFAULT_COUNTRY` | `co` | No | Pre-fills the country input. |
| `VITE_DEFAULT_CHANNEL_ID` | `a1b2c3d4-e5f6-4789-a012-000000000001` | No | Pre-fills the channel clientId. |

> The Vite proxy rewrites `/api/*` → `/*` and `/internal/*` → `/api/v1/internal/*`
> transparently. This avoids CORS preflights in the browser while preserving the
> `aegis-core` URI versioning.

## Architecture

```
src/
├── App.tsx                # Tab routing + global session banner
├── App.css                # All styles (no UI framework)
├── main.tsx
├── components/
│   ├── JsonView.tsx       # Collapsible JSON viewer with copy-to-clipboard
│   ├── KeyValueTable.tsx
│   ├── ResponsePanel.tsx  # HTTP status, JSON, trace
│   └── TabBar.tsx
├── hooks/
│   └── useSessionState.ts # Subscribes to in-memory session
├── lib/
│   ├── actions.ts         # High-level orchestration: createUser, login, logout, introspect, /users/me, refresh
│   ├── api.ts             # Thin axios wrapper for aegis-core endpoints (login/logout use DpopLoginGuard headers, /users/me + refresh use DpopAuthGuard headers)
│   ├── dpop.ts            # Key-pair generation (ES256/RS256/PS256) + DPoP proof builder (with optional tamper)
│   ├── format.ts          # JSON scalar formatting helpers
│   ├── jwe.ts             # RSA-OAEP-256 / A256GCM JWE encryption
│   ├── security-runners.ts# Reusable actions for the Security Test view
│   ├── session.ts         # In-memory session state (phantom tokens, DPoP jkt, jti)
│   └── types.ts
└── views/
    ├── CreateUserView.tsx
    ├── IntrospectView.tsx
    ├── LoginView.tsx
    ├── LogoutView.tsx
    ├── MeView.tsx
    ├── RefreshView.tsx    # Phantom Token rotation (POST /auth/refresh-token)
    ├── SecurityTestView.tsx
    └── SessionView.tsx
```

## How the security mechanisms are exercised

| Aegis mechanism | Where it shows up in the UI |
|---|---|
| JWE envelope (RSA-OAEP-256 + A256GCM) | Tabs 1, 2, 3. The trace shows the plaintext shape and the JWE compact token (truncated). |
| DPoP proof (ES256/RS256/PS256), no `ath` | Tabs 2 (login) and 3 (logout). Header value is `DPoP <jwt>` (with the literal `DPoP ` prefix required by `DpopLoginGuard`). |
| DPoP proof with `ath = base64url(sha256(access))` | Tabs 5 (`/users/me`) and 6 (refresh). Header value is the raw JWT (required by `DpopAuthGuard`). |
| `Authorization: Bearer <access>` | Tab 3 (logout) only. Confusingly, `/users/me` and refresh use `Authorization: DPoP <access>`. |
| `Authorization: DPoP <access>` | Tabs 5, 6. Enforced by `PhantomTokenGuard` (case-sensitive `DPoP ` prefix). |
| Anti-replay (iat + jti in JWE) | Tabs 1, 2, 3. Each request generates a fresh `jti`. |
| Anti-replay (jti in DPoP proof) | All DPoP-protected calls. The server checks Redis (`dpop:jti:<userId>:<jti>`, 5 min TTL). |
| Rate Limiter (10/60s default) | Tabs 1-6. A `429` from aegis-core is rendered with a clear error message. |
| Phantom Token | Visible in the "Session" panel (`access_token`, `refresh_token`, `expires_at`). |
| Internal API Guard | Tab 4. The header `X-Internal-API-Key` is injected by the Vite proxy (server-side). |

## Demo guide

See [`DEMO_GUIDE.md`](./DEMO_GUIDE.md) for the step-by-step execution plan, the
six validation cases required by the Aegis security spec, and the additional
"Security Test" mode buttons.

## Notes

- DPoP private keys live only in the JavaScript heap of the current tab. Reloading
  the page regenerates them; old phantom tokens become unusable (jkt mismatch).
- The "Introspect with expired token" scenario requires waiting for the
  `expires_in` window to elapse (typically 300s). Use the
  "Introspect with invalid token" scenario for an instant `active: false` response.
- This is a development-only demo. Do not ship the `VITE_AEGIS_INTERNAL_API_KEY`
  value to a public client.
