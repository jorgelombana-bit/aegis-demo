# Cómo funciona POST /api/v1/{country}/public/login

## ¿Para qué sirve?

Para hacer login de un usuario existente en Keycloak usando un canal (client) conocido. Es **anónimo** (no requiere nada previo), pero genera credenciales que después se usan para endpoints protegidos.

El flujo real:

1. aegis-core recibe tu request
2. Descifra las credenciales (JWE)
3. Valida que el `jti` no fue usado antes (anti-replay)
4. Valida que `user_identifier === credentials.user_check` (cross-user attack prevention)
5. Valida la prueba DPoP (vincula la sesión al par de claves del browser)
6. Llama a **aegis-admin** por gRPC para verificar membresía user↔client
7. Llama a **Keycloak** con password grant para validar credenciales
8. Si todo OK: genera **phantom tokens** (UUIDs opacos, NO JWTs de Keycloak) y los guarda en Redis
9. Te devuelve `access_token` y `refresh_token` (phantom, no Keycloak)

---

## Lo que necesitás saber antes de hacer la request

| Concepto | Descripción |
|---|---|
| **`country`** | Código ISO alpha-2 lowercase. Resuelve el realm de Keycloak: `puntored-{country}`. |
| **`clientId`** | Keycloak OAuth/OIDC client id del canal (ej: `aegis-AEGIS-DEMO-e8a6cb`). **No** es un UUID. Se usa para: (a) password grant contra Keycloak, (b) validar membresía user↔client vía aegis-admin. |
| **`user_identifier`** | Username o email. Va en el outer body Y en `credentials.user_check` del JWE (deben ser iguales). |
| **`password`** | Contraseña del usuario en Keycloak. Va cifrada dentro del JWE. |
| **`device_context`** | Requerido por el server (a diferencia de Create User). Contiene `fingerprint`, `ip`, `userAgent`. El server lee `userAgent` de acá si no viene en el header HTTP. |
| **DPoP key pair** | Par de claves criptográficas generadas en tu browser. La pública va en el header DPoP, la privada firma las pruebas. Una nueva por sesión de login. |

---

## La request

### HTTP

```
POST /api/v1/{country}/public/login
DPoP: DPoP <compact-jwt>
Content-Type: application/json
```

### Headers

| Header | Requerido | Formato | Ejemplo |
|---|---|---|---|
| `DPoP` | **Sí** | `DPoP <jwt-compact>` (con el prefijo literal `DPoP ` + espacio) | `DPoP eyJ0eXAiOiJkcG9wK2p3dCIs...` |
| `Content-Type` | **Sí** | `application/json` | `application/json` |

**No** hay header `Authorization` (es endpoint público de login).

### Body (outer envelope)

```json
{
  "user_identifier": "user-demo-001",
  "device_context": {
    "fingerprint": "sha256-abc123-demo",
    "ip": "203.0.113.10",
    "userAgent": "MyApp/1.0"
  },
  "secure_payload": "<JWE compact serialization>"
}
```

| Campo | Requerido | Qué es |
|---|---|---|
| `user_identifier` | Sí | El identificador. Debe coincidir con `credentials.user_check` dentro del JWE. |
| `device_context` | **Sí** (a diferencia de Create User) | Objeto con `fingerprint`, `ip`, `userAgent` — todos strings no vacíos. El server lee `userAgent` de acá. |
| `secure_payload` | Sí | JWE compact serialization (5 segmentos joined por `.`) con las credenciales cifradas. |

### Header `DPoP` — la prueba criptográfica

El header `DPoP` es un **JWT firmado con la clave privada de tu browser** (RSA, EC, o EdDSA según lo que generaste). Su propósito: vincular la sesión que se va a crear al par de claves criptográficas de tu browser, para que después nadie pueda usar los tokens sin esa misma clave.

**Estructura del JWT (3 partes base64url joined by `.`):**

```
<header>.<payload>.<signature>
```

#### Header (parte 1)

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "..."
  }
}
```

| Campo | Valor | Significado |
|---|---|---|
| `typ` | `"dpop+jwt"` | Tipo del JWT — debe ser exactamente este string |
| `alg` | `"ES256"` \| `"RS256"` \| `"PS256"` | Algoritmo de firma (debe coincidir con el algoritmo del `jwk`) |
| `jwk` | Objeto JSON | La **clave pública** de tu browser. El server la usa para verificar la firma |

#### Payload (parte 2)

```json
{
  "htm": "POST",
  "htu": "https://aegis-dev.preprodcxr.co/api/v1/co/public/login",
  "iat": 1773670282,
  "jti": "550e8400-e29b-41d4-a716-446655440000"
}
```

| Campo | Tipo | Qué es |
|---|---|---|
| `htm` | string | HTTP method del request — debe ser `"POST"` (porque estás haciendo POST a login) |
| `htu` | string (URL completa) | URL completa del endpoint. Debe coincidir **exactamente** con la URL a la que estás haciendo la request (scheme + host + path) |
| `iat` | integer (unix seconds) | Timestamp de cuándo se generó el DPoP proof. Igual concepto que en `anti_replay.iat`. |
| `jti` | UUID v4 | ID único de este DPoP proof. |

#### Signature (parte 3)

Firma criptográfica calculada sobre `header.payload` usando la clave privada correspondiente al `jwk` público del header.

#### ⚠️ NO incluye `ath` ni `jkt` en el payload

A diferencia de logout y `/users/me`, en login el DPoP proof **NO** tiene:
- `ath` (access token hash) — porque todavía no hay access token
- `jkt` (jwk thumbprint) — el server lo calcula a partir del `jwk` del header

#### Cómo generar el DPoP proof

Con la librería `jose`:

```typescript
import { SignJWT, importJWK } from 'jose';

// 1. Generá tu par de claves (solo una vez por sesión de browser)
const keyPair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  true,
  ['sign', 'verify']
);
const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

// 2. Generá el proof cuando hacés click en "Login"
const proof = await new SignJWT({
  htm: 'POST',
  htu: window.location.origin + '/api/v1/co/public/login',
  iat: Math.floor(Date.now() / 1000),
  jti: crypto.randomUUID()
})
  .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk })
  .sign(keyPair.privateKey);

// 3. Armá el header value con prefijo
const dpopHeader = `DPoP ${proof}`;
```

### Lo que va dentro del JWE

Cuando aegis-core descifra el `secure_payload`, ve:

```json
{
  "credentials": {
    "clientId": "aegis-AEGIS-DEMO-e8a6cb",
    "pass": "Jorge#asd12asdfasdf",
    "user_check": "user-demo-001"
  },
  "anti_replay": {
    "iat": 1773670282,
    "jti": "660e8400-e29b-41d4-a716-446655440001"
  }
}
```

| Campo | Tipo | Qué es |
|---|---|---|
| `credentials.clientId` | string no vacío | Keycloak OAuth client id del canal. **No** es UUID. |
| `credentials.pass` | string no vacío | La contraseña del usuario en plaintext (va cifrada dentro del JWE). |
| `credentials.user_check` | string no vacío | **Debe ser igual al `user_identifier` del outer body.** |
| `anti_replay.iat` | integer (unix seconds) | Timestamp. Igual concepto que en Create User. |
| `anti_replay.jti` | UUID v4 | Único por cada request. No reutilizable en la ventana de validez (cacheado en Redis). |

> **Nota técnica**: el DTO `PublicHumanLoginDecryptedPayloadDto` declara un campo `user_identifier` (línea 13), pero el interceptor `JweDecryptInterceptor` **no** lo lee del JWE — lo sobrescribe con el del outer body (línea 177). En la práctica podés omitirlo del JWE.

---

## Lo que recibís

### ✅ Éxito: 200 OK

```json
{
  "access_token": "550e8400-e29b-41d4-a716-446655440001",
  "refresh_token": "550e8400-e29b-41d4-a716-446655440002",
  "expires_in": 300,
  "token_type": "DPoP"
}
```

| Campo | Tipo | Qué es |
|---|---|---|
| `access_token` | UUID v4 | **Phantom access token** — NO es un JWT de Keycloak. Es un UUID opaco que referencia una sesión guardada en Redis (key: `session:access:{sha256(token)}`). |
| `refresh_token` | UUID v4 | **Phantom refresh token** — igual concepto. Key Redis: `session:refresh:{sha256(token)}`. |
| `expires_in` | integer (segundos) | Tiempo de vida del access token. Después de esto el access token expira (default ~300s = 5 min). |
| `token_type` | string | Siempre `"DPoP"`. Indica que para usar estos tokens necesitás probar que tenés la clave DPoP (vía header `Authorization: DPoP <access>` + header `DPoP <proof con ath>`). |

### Qué hacer con los tokens

Para **todos los endpoints protegidos** (logout, /users/me, /auth/refresh-token):

```
Authorization: DPoP <access_token>
DPoP: <DPoP proof firmado con la MISMA clave del login + claim ath>
```

Donde el `ath` del nuevo proof es `base64url(sha256(access_token))`. El server valida que la `jkt` (thumbprint del jwk) del proof coincida con la `jkt` guardada en la sesión phantom al momento del login. Esto previene que alguien robe el access_token y lo use sin la clave privada.

### ❌ Errores

| Status | `error` | Cuándo |
|---|---|---|
| `400` | `invalid_request` | Validación falla: country mal formado, body mal formado, JWE mal descifrado, `clientId` vacío, DTO inválido. |
| `401` | `invalid_request` | `user_identifier !== credentials.user_check`, DPoP inválido (firma, htm, htu, iat fuera de ventana), jti ya usado, Keycloak rechazó credenciales. |
| `401` | (sin `error`) `DPOP_HTU_MISMATCH` / `DPOP_AUTH_SCHEME_MISMATCH` / etc. | Errores específicos de DPoP. |
| `429` | `invalid_request` | Rate limit excedido. |
| `502` | `invalid_request` | Keycloak no responde o falló (error de upstream, no del cliente). |

Body de error siempre OAuth-style: `{ error: string, error_description: string }`.

---

## Ejemplo completo (pseudo-código)

```typescript
import { CompactEncrypt, importJWK, SignJWT } from 'jose';

// === PASO 1: Obtener la clave JWE ===
const jwkResponse = await fetch('https://aegis.example.com/api/v1/auth/encryption-key');
const { data: jwk } = await jwkResponse.json();

// === PASO 2: Generar par de claves DPoP (una sola vez por sesión de browser) ===
const keyPair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  true, ['sign', 'verify']
);
const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

// === PASO 3: Cifrar credenciales con JWE ===
const iat = Math.floor(Date.now() / 1000);
const jti = crypto.randomUUID();

const jwePayload = {
  credentials: {
    clientId: 'aegis-AEGIS-DEMO-e8a6cb',
    pass: 'Jorge#asd12asdfasdf',
    user_check: 'user-demo-001'  // ← igual a user_identifier del outer
  },
  anti_replay: { iat, jti }
};

const jwe = await new CompactEncrypt(
  new TextEncoder().encode(JSON.stringify(jwePayload))
)
  .setProtectedHeader({ alg: jwk.alg, enc: 'A256GCM' })
  .encrypt(await importJWK(jwk, jwk.alg));

// === PASO 4: Generar DPoP proof ===
const url = 'https://aegis.example.com/api/v1/co/public/login';
const dpopProof = await new SignJWT({
  htm: 'POST',
  htu: url,
  iat: Math.floor(Date.now() / 1000),
  jti: crypto.randomUUID()
})
  .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk })
  .sign(keyPair.privateKey);

// === PASO 5: Enviar la request ===
const response = await fetch(url, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'DPoP': `DPoP ${dpopProof}`  // ← con prefijo "DPoP " + espacio
  },
  body: JSON.stringify({
    user_identifier: 'user-demo-001',  // ← igual a credentials.user_check
    device_context: {
      fingerprint: 'sha256-abc123-demo',
      ip: '203.0.113.10',
      userAgent: 'MyApp/1.0'
    },
    secure_payload: jwe
  })
});

const tokens = await response.json();
// tokens.access_token, tokens.refresh_token, tokens.expires_in, tokens.token_type
```

---

## Resumen de reglas críticas

1. **`user_identifier` del outer body** y **`credentials.user_check` del JWE** deben ser **exactamente el mismo string**. Si difieren → 401.

2. **Header `DPoP`** debe tener el formato **`DPoP <jwt>`** con el prefijo literal `DPoP ` (mayúscula) + espacio. Sin este prefijo → 401 `AUTHORIZATION_SCHEME_MISMATCH`.

3. **DPoP proof debe tener** `typ: "dpop+jwt"` en el header, `alg` ∈ `{ES256, RS256, PS256}`, `jwk` con la clave pública.

4. **DPoP proof `htu`** debe ser la URL completa del endpoint (scheme + host + path). Si tu URL real difiere → 401 `DPOP_HTU_MISMATCH`.

5. **`device_context` es requerido** (a diferencia de Create User). Los 3 sub-campos (`fingerprint`, `ip`, `userAgent`) son strings no vacíos.

6. **`anti_replay.jti`** debe ser único por cada request. Reusar el mismo jti → 401 replay detected.

7. **`anti_replay.iat`** debe estar dentro de la ventana de validez del server (centrado en `now` con un clock skew).

8. **Los tokens que recibís son UUIDs opacos (phantom tokens), NO son JWTs de Keycloak.** Para usarlos en endpoints protegidos necesitás probar posesión de la clave DPoP con la que hiciste login.

9. **El `clientId`** es el Keycloak OAuth client id (string arbitrario, no UUID). Se reenvía tal cual a Keycloak y a aegis-admin para validar membresía.

10. **Login es anónimo pero no sin estado**: genera un rate limit por IP (no por usuario, porque todavía no estás autenticado).

---

## Lo que NO se puede deducir del código

- **Valores exactos del rate limit**: configurables vía env vars.
- **Ventana exacta del anti_replay** (cuánto vive un jti en Redis, cuánto clock skew): configurable vía env vars.
- **Política de contraseñas que Keycloak aplica**: vive en Keycloak, no en aegis-core.
- **TTL exacto de la sesión phantom**: probablemente igual a `expires_in` de Keycloak, pero el valor exacto está en la configuración.
- **Mapeo exacto de errores de Keycloak a HTTP status**: `loginHuman` traduce errores de Keycloak, pero los detalles exactos de cada traducción están en `resolveHumanLoginUnauthorizedMessage` (línea 273-287 de `authenticated-client.service.ts`) — solo sé que `invalid_grant` → "invalid credentials".