# Cómo funciona la autenticación M2M (Machine-to-Machine) con `MachineMachineStrategy`

## ¿Qué es M2M?

Es la autenticación **entre servicios backend** usando el endpoint `POST /auth/{country}/token`. Un servicio (cliente) se autentica contra aegis-core usando sus propias credenciales (client_id + client_secret) para obtener un **AEGIS token** que después usa para llamar otros endpoints protegidos.

Usa **HTTP Basic Auth** estándar. No hay DPoP, no hay JWE, no hay anti-replay. Es el flujo más simple de los 3 disponibles.

## ¿Qué pasa internamente?

El flujo M2M hace un "doble cambio" — Keycloak firma el token original, después aegis-core lo **re-firma** con su propia clave para crear un AEGIS token con claims custom:

```
Tu servicio                                          aegis-core                              Keycloak
     │                                                     │                                     │
     │  POST /auth/co/token                                │                                     │
     │  Authorization: Basic <base64(clientId:secret)>     │                                     │
     ├─────────────────────────────────────────────────────►│                                     │
     │                                                     │                                     │
     │                                                     │  POST /realms/puntored-co/          │
     │                                                     │  protocol/openid-connect/token       │
     │                                                     │  grant_type=client_credentials       │
     │                                                     │  client_id=...&client_secret=...    │
     │                                                     ├────────────────────────────────────►│
     │                                                     │                                     │
     │                                                     │  { access_token: <Keycloak JWT>,    │
     │                                                     │    expires_in, scope, token_type }   │
     │                                                     │◄─────────────────────────────────────┤
     │                                                     │                                     │
     │                                                     │  Validates Keycloak JWT              │
     │                                                     │  (alg, exp, aud, azp, ...)            │
     │                                                     │                                     │
     │                                                     │  Re-signs as AEGIS token              │
     │                                                     │  (signed with AEGIS private key)     │
     │                                                     │                                     │
     │  { access_token: <AEGIS JWT>,                      │                                     │
     │    expires_in, scope, token_type: "Bearer" }       │                                     │
     │◄─────────────────────────────────────────────────────┤                                     │
```

### ¿Por qué re-firmar?

Keycloak te da un JWT firmado con la clave de Keycloak. aegis-core lo **re-firma** con su propia clave privada para crear un **AEGIS token** que:

- Tiene claims custom de aegis (`is_aegis`, `is_m2m`, `aud: ['aegis-internal', 'core-api']`)
- Está firmado con la clave de aegis (no de Keycloak)
- Tiene la audiencia correcta para los servicios internos de aegis

Cuando un servicio interno de aegis ve un token, valida la firma contra la clave pública de aegis — no necesita contactar Keycloak.

---

## El endpoint: `POST /auth/{country}/token`

### La request

```
POST /auth/co/token
Authorization: Basic <base64(clientId:clientSecret)>
Content-Type: application/json
```

### Headers

| Header | Requerido | Formato |
|---|---|---|
| `Authorization` | **Sí** | `Basic <base64(clientId:clientSecret)>` — el header estándar HTTP Basic |
| `Content-Type` | Recomendado | `application/json` |

### Body

**Vacío**. El endpoint no lee el body. Solo importa el header `Authorization`.

### ¿Cómo armar el header `Authorization`?

```typescript
const clientId = 'tu-client-id';
const clientSecret = 'tu-client-secret';

// 1. Concatenar clientId:clientSecret
const credentials = `${clientId}:${clientSecret}`;

// 2. Codificar en base64
const base64 = Buffer.from(credentials).toString('base64');

// 3. Armar el header
const authHeader = `Basic ${base64}`;
```

O con `btoa` en browser:

```typescript
const authHeader = `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
```

> **Nota**: el estándar HTTP Basic usa base64 estándar (no base64url). La librería `Buffer.from(...).toString('base64')` o `btoa()` lo hacen correctamente.

### La response

```json
{
  "code": 200,
  "message": "Login successful",
  "data": {
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMyJ9...",
    "expires_in": 300,
    "scope": "email profile",
    "token_type": "Bearer"
  }
}
```

| Campo | Tipo | Qué es |
|---|---|---|
| `code` | number | Siempre 200 en éxito |
| `message` | string | Siempre `"Login successful"` |
| `data.access_token` | JWT string | **AEGIS token** (NO el JWT de Keycloak). Firmado con la clave privada de aegis. |
| `data.expires_in` | number | Segundos hasta expiración |
| `data.scope` | string | Scopes del token (vienen de Keycloak) |
| `data.token_type` | string | Siempre `"Bearer"` |

> **No hay `refresh_token`** en M2M. Cuando expira, simplemente hacés otro `POST /auth/{country}/token` con las mismas credenciales.

### ¿Qué tiene el AEGIS token dentro?

El `access_token` es un JWT firmado con RS256 (u otro FIPS-approved algorithm). Claims que produce aegis:

```json
{
  "sub": "<client_id>",
  "azp": "<client_id>",
  "client_id": "<client_id>",
  "aud": ["aegis-internal", "core-api"],
  "scope": "email profile",
  "roles": [...],
  "is_aegis": true,
  "is_m2m": true,
  "iat": 1773670282,
  "exp": 1773670582,
  "iss": "https://aegis-dev.preprod"
}
```

> **Diferencia clave vs el JWT de Keycloak**: el AEGIS token NO es de Keycloak. Fue **re-firmado** por aegis-core con su propia clave privada. Si intentás validarlo contra las JWKS de Keycloak, falla.

### Cómo usar el token en requests posteriores

```
GET /api/v1/some-endpoint
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

(Mismo patrón que cualquier token Bearer — header `Authorization: Bearer <token>`).

### Errores

| Status | `error` | Cuándo |
|---|---|---|
| `400` | `Invalid country code` | `country` no matchea `^[a-z]{2}$` (debe ser lowercase, 2 letras) |
| `401` | `Invalid authorization` | Header `Authorization` no empieza con `Basic ` |
| `401` | `Invalid client id or secret` | El base64 se descifró pero `clientId` o `clientSecret` están vacíos |
| `401` | `Invalid credentials` | Keycloak rechazó las credenciales (`invalid_client`) |
| `429` | `Too many requests` | Rate limit excedido (per `clientId`) |
| `500` | `Token signing failed` / `Signing key not available` | Error interno de aegis (clave de firma no disponible) |
| `502` | `Bad gateway` | Error interno no esperado |

Body de error: `{ code: <number>, message: <string>, data: null }` (formato `ThStandardResponse`).

---

## Lo que hace `MachineMachineStrategy` internamente

`MachineMachineStrategy.process(token, client)` toma el `AuthTokenDto` que devuelve Keycloak (vía `client_credentials` grant) y:

1. **Parsea el access_token de Keycloak como JWT** → extrae `sub`, `iss`, `azp`, `aud`, `exp`, `iat`, `scope`, `realm_access`, `resource_access`, etc.

2. **Valida el token de Keycloak** contra la trust policy:
   - Todos los claims requeridos presentes (`sub`, `iss`, `azp`, `typ`, `alg`, `aud`)
   - `typ === 'Bearer'`
   - `alg` está en la lista FIPS-approved: `RS256/RS384/RS512/PS256/PS384/PS512/EdDSA`
   - `exp > now` (no expirado)
   - `nbf <= now` (si está presente)
   - `iat <= now + 60` y `iat <= exp`
   - `aud` incluye alguno de los `expectedInputAudiences` configurados
   - Si `context.clientId` está presente, `azp === context.clientId`

3. **Re-firma como AEGIS token** con los claims:
   ```
   sub, azp, client_id, aud (output), scope, roles,
   is_aegis: true, is_m2m: true
   ```
   Firmado con RS256 (o el algoritmo configurado en `AEGIS_JWS_ALG`).

4. **Retorna el AuthTokenDto modificado** con:
   - `access_token` reemplazado por el AEGIS token
   - `expires_in` reemplazado por el `expiresIn` del AEGIS token
   - `token_type` forzado a `"Bearer"`
   - `scope` y otros campos preservados

---

## Cómo validar el AEGIS token (lado receptor)

Si tu servicio valida el AEGIS token, lo hacés con **JWKS**:

```
GET /.well-known/aegis-core/jwks.json
```

Devuelve:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "...",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

Verificás:
1. Firma con la clave pública del JWKS (alg debe ser RS256/RS384/RS512/PS256/PS384/PS512)
2. `iss` debe ser `AEGIS_TOKEN_ISSUER` (default `https://aegis-dev.preprod`)
3. `aud` debe incluir uno de los audiences esperados
4. `exp` debe ser futuro
5. `is_aegis: true` (para distinguirlo de tokens de Keycloak)

---

## Ejemplo completo M2M (pseudo-código)

```typescript
// === PASO 1: Obtener el token M2M ===
const clientId = 'mi-servicio-client';
const clientSecret = process.env.MY_CLIENT_SECRET;

const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

const response = await fetch('https://aegis.example.com/auth/co/token', {
  method: 'POST',
  headers: {
    'Authorization': `Basic ${credentials}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({})  // body vacío
});

const { data: { access_token, expires_in } } = await response.json();
// access_token es el AEGIS token (JWT firmado con RS256)
// expires_in es segundos hasta expiración

// === PASO 2: Usar el token en requests posteriores ===
const apiResponse = await fetch('https://aegis.example.com/api/v1/some-endpoint', {
  headers: {
    'Authorization': `Bearer ${access_token}`
  }
});

// === PASO 3: Cuando expire, obtener uno nuevo (M2M tokens no tienen refresh) ===
// Simplemente repetís el paso 1 — para M2M siempre se hace client_credentials
```

---

## Variables de entorno requeridas (lado aegis-core)

| Variable | Default | Para qué se usa |
|---|---|---|
| `KEYCLOAK_BASE_URL` | `http://localhost:8080` | URL de Keycloak (donde se manda `client_credentials`) |
| `KEYCLOAK_REALM_PREFIX` | `puntored` | Prefijo del realm: `${prefix}-${country}` |
| `AEGIS_JWS_PRIVATE_KEY_PEM` | (requerido) | Clave privada para **firmar el AEGIS token** |
| `AEGIS_JWS_KEY_ID` | `''` | `kid` del header del AEGIS token |
| `AEGIS_JWS_ALG` | `RS256` | Algoritmo de firma del AEGIS token |
| `AEGIS_TOKEN_ISSUER` | `https://aegis-dev.preprod` | Claim `iss` del AEGIS token |
| `AEGIS_RESIGN_OUTPUT_AUDIENCES` | `'aegis-internal,core-api'` | Claim `aud` del AEGIS token |
| `AEGIS_RESIGN_INPUT_AUDIENCES` | `'aegis-core'` | Audience esperada en el Keycloak token (para validación de trust) |
| `RATE_LIMIT_LIMIT` | `10` | Máximo de requests por ventana |
| `RATE_LIMIT_TTL` | `60` | Ventana del rate limit en segundos |
| `RATE_LIMIT_FAIL_CLOSED` | `false` | Si Redis falla, ¿bloquear (true) o dejar pasar (false)? |

---

## Reglas críticas

1. **Header `Authorization` debe ser `Basic <base64>`** (con espacio después de "Basic"). El base64 es de `clientId:clientSecret` (no base64url).

2. **Body de la request es irrelevante** — el endpoint solo lee el header. Podés mandar `{}` o nada.

3. **El token que recibís es AEGIS, NO Keycloak**. Fue re-firmado por aegis-core. Si intentás validarlo contra JWKS de Keycloak, falla.

4. **M2M tokens NO tienen `refresh_token`**. Cuando expira, simplemente hacés otro `POST /auth/{country}/token` con las mismas credenciales.

5. **El rate limit es por `clientId`**, no por IP. Si tu servicio hace muchas requests M2M, contás contra tu propio límite.

6. **El AEGIS token se firma con RS256** (o el algoritmo configurado en `AEGIS_JWS_ALG`). Debe ser FIPS-approved.

7. **El AEGIS token tiene claims custom**: `is_aegis: true`, `is_m2m: true`, `aud: [aegis-internal, core-api]`. Usá `is_aegis` para distinguirlo de tokens de Keycloak.

8. **No hay DPoP en M2M**. El header `DPoP` no se valida. Solo Basic Auth.

9. **No hay anti-replay en M2M**. Solo en login humano público y admin login.

---

## Lo que NO se puede deducir del código

- **Valores exactos de los defaults de env vars** (más allá de lo listado en `envs.config.ts`): los defaults exactos no están en el código que leí.
- **El schema exacto del proto gRPC `aegis-admin`**: no está en este repo (es un paquete externo `@puntored-tech/aegis-api-contracts`).
- **Comportamiento exacto de Keycloak** cuando recibe `client_credentials` grant: vive en Keycloak, no en aegis-core.