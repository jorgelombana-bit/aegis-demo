# Aegis Demo UI — Guía de ejecución de pruebas

Esta guía documenta cómo ejecutar la demo de los **flujos de seguridad de Aegis** desde
la UI React (`AEGIS-DEMO/`, antes `utils-mixed/temp-login/frontend`). La UI consume
**directamente** `aegis-core` mediante el proxy de Vite, sin backend propio.

> El contrato exacto de cada endpoint está en [`AEGIS_DEMO.md`](./AEGIS_DEMO.md).
> Si algo difiere entre este documento y la basecode de aegis-core,
> `AEGIS_DEMO.md` es la fuente de verdad.

---

## 1. Prerrequisitos

| Componente        | Versión  | Notas |
|-------------------|----------|-------|
| Node.js           | ≥ 20     | `node -v` |
| pnpm              | ≥ 9      | `pnpm -v` |
| aegis-core        | dev/preprod | Debe ser accesible desde la máquina del usuario. |
| Keycloak          | Cualquiera | Cubre los realms `puntored-{country}`. |
| Redis             | Cualquiera | Requerido por aegis-core (anti-replay, phantom sessions, rate limit). |

Configuración de aegis-core (mínima):

- `AEGIS_PUBLIC_ORIGIN` debe apuntar al **host público** que el navegador ve en la URL
  (porque se usa para validar `htu` del DPoP). Por defecto:
  `https://aegis-dev.preprodcxr.co`.
- `INTERNAL_API_KEY` debe existir (se inyecta server-side por el proxy de Vite).
- `AEGIS_JWE_PRIVATE_KEY_PEM` + `AEGIS_JWE_ALG=RSA-OAEP-256` o `ECDH-ES+A256KW`.
- `AEGIS_JWS_PRIVATE_KEY_PEM` con su `AEGIS_JWS_KEY_ID`.
- Rate limit por defecto: 10 req / 60s. El DPoP `jti` tiene 5 min de TTL.
- Anti-replay por defecto: 5 min, `fail-closed = true`.

## 2. Setup

```bash
cd AEGIS-DEMO
pnpm install
cp .env.example .env
# Editar .env: VITE_AEGIS_INTERNAL_API_KEY=<el valor real de aegis-core>
pnpm dev
# Abre http://localhost:5173
```

> Si `VITE_AEGIS_INTERNAL_API_KEY` está vacío, el proxy añade el header
> `X-Internal-API-Key: ` y la UI fallará al hacer introspección. Cualquier otro
> endpoint sigue funcionando.

Variables de entorno disponibles (todas opcionales excepto `VITE_AEGIS_INTERNAL_API_KEY`):

```env
VITE_AEGIS_PROXY_TARGET=https://aegis-dev.preprodcxr.co
VITE_AEGIS_PUBLIC_ORIGIN=https://aegis-dev.preprodcxr.co
VITE_AEGIS_INTERNAL_API_KEY=<valor real>
VITE_DEFAULT_COUNTRY=co
VITE_DEFAULT_CHANNEL_ID=a1b2c3d4-e5f6-4789-a012-000000000001
```

## 3. Cómo navega la UI a través de los flujos

| Pestaña                  | Endpoint aegis-core                                     | Mecanismos ejercidos |
|--------------------------|---------------------------------------------------------|----------------------|
| 1. Create User           | `POST /api/v1/{country}/public/user`                   | JWE (RSA-OAEP-256 + A256GCM), Rate Limiter |
| 2. Login                 | `POST /api/v1/{country}/public/login`                  | JWE + DPoP (ES256/RS256/PS256) + Anti-replay + Rate Limit (header `DPoP: DPoP <jwt>`) |
| 3. Logout                | `POST /api/v1/{country}/public/logout`                 | JWE + DPoP + `Authorization: Bearer <access>` + Rate Limit |
| 4. Introspect            | `POST /api/v1/internal/token/introspect` (vía proxy)    | Internal API Guard (`X-Internal-API-Key` inyectado por el proxy) |
| 5. /users/me             | `GET /api/v1/users/me`                                  | `Authorization: DPoP <access>` + DPoP (con `ath`) + Rate Limit |
| 6. Refresh               | `POST /api/v1/auth/refresh-token`                       | `Authorization: DPoP <access>` + DPoP (con `ath`) + JSON body + Rate Limit |
| 7. Security Test         | Combinaciones de los anteriores                        | Escenarios fallidos one-click |

Cada click muestra:
- HTTP status y cuerpo parseado.
- Trace paso a paso (cifrado JWE, DPoP proof, headers, etc.).
- Badge `success`/`rejected` en la esquina superior.

## 4. Escenarios de éxito (los 6 del enunciado)

### 4.1 Crear usuario (caso 1)

1. Ir a **1. Create User**.
2. Completar `country`, `channelId` (UUID), `username`, `email`, `password` (≥ 10 chars).
3. Click **Create User**.
4. Verificar respuesta 201 con `{ message: "..." }`.

Equivalente curl (omitido, se hace por UI; el trace de la UI muestra el body JWE real
y la respuesta de aegis-core).

### 4.2 Login con Phantom Token + DPoP (caso 2)

1. Asegurarse de que el usuario existe (pestaña 1) y existe en Keycloak.
2. Ir a **2. Login**.
3. Seleccionar algoritmo DPoP (`ES256` por defecto).
4. Completar credenciales y click **Login**.
5. La UI debe mostrar HTTP 200 con:
   ```json
   {
     "access_token": "550e8400-e29b-41d4-a716-446655440001",
     "refresh_token": "550e8400-e29b-41d4-a716-446655440002",
     "expires_in": 300,
     "token_type": "DPoP"
   }
   ```
6. La pestaña "Session" (header) debe mostrar el `jkt` y el algoritmo en uso.

### 4.3 Logout (caso 3)

1. Con sesión activa (pestaña 5 → `200 OK`).
2. Ir a **3. Logout**.
3. Click **Logout**.
4. Esperar HTTP 204 (la UI reporta el status aunque la respuesta sea vacía).

### 4.4 Introspect (caso 4)

1. Con sesión activa, copiar el `access_token` desde la pestaña "Session".
2. Ir a **4. Introspect**.
3. Pegar el UUID, click **Introspect**.
4. Esperar HTTP 200 con `active: true` y todos los claims:
   ```json
   {
     "active": true,
     "sub": "<userId>",
     "country": "co",
     "client_id": "<channelId>",
     "roles": ["USER"],
     "dpop_jkt": "<jkt del login>",
     "iat": ...,
     "exp": ...
   }
   ```

## 5. Validación de Seguridad DPoP (los 6 casos del enunciado)

Estos casos usan la pestaña **5. /users/me** y la pestaña **6. Security Test**.

### Caso 1 — Phantom Token y DPoP válidos → 200 OK
- Pestaña **5. /users/me** → click → 200.
- El `dpop_jkt` de la sesión (devuelto por introspect) coincide con el `jkt` del DPoP
  proof actual.

### Caso 2 — Reutilización de Phantom Token con DPoP diferente → 401
- Pestaña **6. Security Test** → click **"/users/me con DPoP diferente (jkt)"**.
- Resultado: HTTP 401 con `error_description: "DPOP_JKT_MISMATCH"`.
- Verificación: la UI genera un par de claves nuevo y firma con ese jkt; aegis-core
  compara el jkt del header DPoP contra `dpop_jkt` en Redis y rechaza.

### Caso 3 — DPoP alterado → 401
- Pestaña **6. Security Test** → click **"Login con DPoP alterado (htu)"**.
- Resultado: HTTP 401 con `error_description: "DPOP_HTU_MISMATCH"`.
- Verificación: la UI firma un DPoP con `htu` apuntando a otra URL; el guard valida
  `payload.htu === buildDpopTargetUri(request)` y falla.

### Caso 4 — Phantom Token inválido → 401
- Pestaña **6. Security Test** → click **"/users/me con Phantom Token inválido"**.
- Resultado: HTTP 401 con `error_description` de `PHANTOM_TOKEN_NOT_FOUND`.
- Verificación: aegis-core intenta resolver el token contra Redis y no lo encuentra.

### Caso 5 — Logout con DPoP inválido → 401
- Pestaña **7. Security Test** → click **"Logout con DPoP diferente (jkt)"**.
- Resultado: HTTP 401 con `error_description` de Phantom session mismatch
  (la comparación ocurre en `PublicHumanLogoutHandler.assertLogoutSessionsMatch`).
- Verificación: el handler compara el `dpop_jkt` del DPoP proof contra el `dpop_jkt`
  persistido en Redis para la sesión y rechaza.

### Caso 6 — Introspect con token inválido → `active: false`
- Pestaña **7. Security Test** → click **"Introspect con token inválido"**.
- Resultado: HTTP 200 con `{ "active": false }`.
- Verificación: aegis-core busca el UUID en Redis; si no existe (o está expirado),
  responde `active: false` según RFC 7662.

## 6. Modo Test de Seguridad (recomendado, botones one-click)

La pestaña **7. Security Test** ofrece los siguientes botones one-click:

| # | Botón                                              | Esperado |
|---|----------------------------------------------------|----------|
| 1 | Login válido (Phantom + DPoP correctos)            | 200 (con phantom tokens) |
| 2 | Login con DPoP alterado (htu)                      | 401 DPOP_HTU_MISMATCH |
| 3 | Logout con DPoP diferente (jkt)                    | 401 Phantom session mismatch |
| 4 | /users/me con Phantom Token inválido               | 401 Unauthorized |
| 5 | /users/me con DPoP diferente (jkt)                 | 401 DPOP_JKT_MISMATCH |
| 6 | Introspect con token inválido                      | 200 `{ active: false }` |
| 7 | Introspect con token expirado                      | 200 `{ active: false }` después del `expires_in` |

### Procedimiento para "Introspect con token expirado"

Como el `expires_in` típico de aegis-core es 300s, este caso es el único que **requiere
espera**. Procedimiento recomendado:

1. Inicia sesión en la pestaña 2.
2. Confirma que tienes un phantom access token (pestaña "Session" muestra
   `expires_at` en ISO 8601).
3. Espera hasta que la hora actual supere ese timestamp.
4. Click **"Introspect con token expirado"**.
5. La UI ya no mostrará la alerta de "aún no ha expirado".

Alternativa equivalente (no requiere espera): usa el botón **"Introspect con token
inválido"**; la respuesta también es `{ active: false }` pero el motivo es "no existe
en Redis" en lugar de "expirado por TTL". Ambos casos verifican el contrato RFC 7662.

## 7. Evidencia visual esperada

Para documentar la demo, captura estas pantallas:

1. **Pestaña 2 — Login exitoso** con `access_token`, `refresh_token`, `dpop_jkt`
   visible en el trace.
2. **Pestaña 5 — /users/me** con `200 OK` y `userId`, `roles`.
3. **Pestaña 6 — Refresh** con `200 OK` y nuevos phantom tokens.
4. **Pestaña 4 — Introspect** con la respuesta completa incluyendo `dpop_jkt`.
5. **Pestaña 7 — /users/me con DPoP diferente (jkt)** con `401` y badge rojo
   `rejected`.
6. **Pestaña 7 — Introspect con token inválido** con `200 OK` y `active: false`.

## 8. Troubleshooting

| Síntoma                                                | Causa probable                                  |
|--------------------------------------------------------|--------------------------------------------------|
| `encryption-key failed: HTTP 502`                      | aegis-core no tiene la JWE private key cargada. |
| `DPOP_JKT_MISMATCH` en login válido                   | El navegador cacheó un DPoP jkt antiguo. Reset session. |
| `RATE_LIMITED` tras varios clicks                     | aegis-core aplica 10/60s por IP. Espera 60s o cambia de IP. |
| `Missing internal api key`                             | `VITE_AEGIS_INTERNAL_API_KEY` no está en `.env`. |
| `CORS error` en consola del browser                   | El origin no está en `CORS_ORIGINS` de aegis-core. |
| `iat_too_old`                                          | El reloj del equipo está desincronizado. |
