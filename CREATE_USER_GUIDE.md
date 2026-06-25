# Cómo funciona POST /api/v1/{country}/public/user

## ¿Para qué sirve?

Para registrar un usuario nuevo en Keycloak usando un canal (client) existente. Es **anónimo** (no requiere login previo) y está pensado para auto-registro público.

Internamente: aegis-core recibe tu request, descifra las credenciales, valida la membresía del usuario en el canal, y llama a **aegis-admin** por gRPC para crear el usuario en Keycloak.

---

## Lo que necesitás antes de hacer la request

### 1. Obtener la clave pública JWE

**Request:**
```
GET /api/v1/auth/encryption-key
```

**Response:**
```json
{
  "code": 200,
  "message": "public encryption key retrieved successfully",
  "data": {
    "kty": "RSA",
    "n": "<base64url del modulus>",
    "e": "AQAB",
    "kid": "<identificador>",
    "use": "enc",
    "alg": "RSA-OAEP-256"
  }
}
```

> El campo `data.alg` te dice qué algoritmo de cifrado usar. Solo se aceptan `RSA-OAEP-256` o `ECDH-ES+A256KW` (con EC key). El `enc` siempre es `A256GCM`.

### 2. Lo que tenés que saber

| Concepto | Descripción |
|---|---|
| **`country`** | Código ISO alpha-2 lowercase del país. Se usa para resolver el **realm de Keycloak** con el formato `puntored-{country}`. Ejemplo: `co` → realm `puntored-co`. |
| **`clientId`** | El **Keycloak OAuth/OIDC client id** del canal (p. ej. `aegis-AEGIS-DEMO-e8a6cb`). **No** es un UUID, es un string arbitrario. Se reenvía tal cual a aegis-admin. |
| **`user_identifier`** | El identificador del usuario. Se envía **dos veces**: una en el outer body y otra dentro del JWE (`credentials.user_check`). Deben ser **exactamente iguales**. Si difieren → 400. |

---

## La request

### HTTP

```
POST /api/v1/{country}/public/user
Content-Type: application/json
```

### Body (outer envelope)

```json
{
  "user_identifier": "user-demo-001",
  "secure_payload": "<JWE compact serialization>",
  "device_context": {              // OPCIONAL
    "fingerprint": "...",
    "ip": "...",
    "userAgent": "..."
  }
}
```

| Campo | Requerido | Qué es |
|---|---|---|
| `user_identifier` | Sí | El identificador. Debe coincidir con `credentials.user_check` dentro del JWE. |
| `secure_payload` | Sí | El JWE compact serialization (5 segmentos joined por `.`) con las credenciales cifradas. |
| `device_context` | No | Objeto libre. Si lo mandás, tiene que ser un objeto (no array, no null). El server no lee ni valida sus campos internos. |

### Headers opcionales

| Header | Efecto |
|---|---|
| `x-trace-id` | Se propaga a aegis-admin gRPC. Usado para trazabilidad distribuida. |
| `x-correlation-id` | Igual que trace-id. |
| `user-agent` | Si no se manda, el server pone `'aegis-core/http'` por default. Se propaga a aegis-admin. |

No hay header `DPoP` ni `Authorization` (es endpoint público).

---

## Lo que va dentro del JWE

El JWE es un objeto JSON cifrado con la clave pública del paso 1. Cuando aegis-core lo descifra, ve esto:

```json
{
  "clientId": "aegis-AEGIS-DEMO-e8a6cb",
  "userData": {
    "username": "user-demo-001",
    "email": "user-demo-001@example.com",
    "password": "Jorge#asd12asdfasdf"
  },
  "credentials": {
    "user_check": "user-demo-001"
  },
  "anti_replay": {
    "iat": 1773670282,
    "jti": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### Cada campo

| Campo | Tipo | Qué es / qué restricción tiene |
|---|---|---|
| `clientId` | string no vacío | Keycloak OAuth client id del canal. Se reenvía a aegis-admin tal cual. |
| `userData.username` | string no vacío | El nombre de usuario en Keycloak. |
| `userData.email` | string (formato email) | El email del usuario. |
| `userData.password` | string no vacío | La contraseña en plaintext (dentro del JWE, así que va cifrada). aegis-admin aplica la política de password del canal. |
| `credentials.user_check` | string no vacío | **Debe ser exactamente igual al `user_identifier` del outer body.** Si no coinciden → 400. |
| `anti_replay.iat` | integer (unix seconds) | Timestamp de cuándo se generó la request. Debe estar dentro de una ventana de validez (default ±300s + clock skew). Si es muy viejo o muy futuro → 401. |
| `anti_replay.jti` | UUID v4 | Identificador único de la request. **No** se puede reusar dentro de la ventana de validez (se guarda en Redis). Si reusás el mismo jti → 401 replay detected. |

### Cómo generar el anti_replay

```typescript
const iat = Math.floor(Date.now() / 1000);
const jti = crypto.randomUUID();
// Usar `iat` y `jti` UNA SOLA VEZ por request.
```

---

## Lo que recibís

### ✅ Éxito: 201 Created

```json
{
  "message": "Registration successful. Sign in with your credentials."
}
```

El usuario fue creado en Keycloak. Ahora podés hacer login con `POST /api/v1/{country}/public/login` usando las mismas credenciales.

### ❌ Errores

| Status | `error` | Cuándo |
|---|---|---|
| `400` | `invalid_request` | Validación falla: country mal formado, outer body mal formado, JWE mal formado, `user_check !== user_identifier`, DTO inválido, `anti_replay` mal formado, etc. |
| `401` | `invalid_request` | JWE decryption falló (clave incorrecta, alg/enc no soportado, etc.) o anti-replay rechazó (`iat` fuera de ventana, `jti` ya usado, formato inválido). |
| `409` | `already_exists` | El username o email ya existe en Keycloak. |
| `429` | `invalid_request` | Rate limit excedido. El server acepta N requests por ventana de tiempo (configurable). |
| `502` | `invalid_request` | aegis-admin no responde o falló. Es un error de upstream, no del cliente. |

El body de error siempre tiene la forma `{ error: string, error_description: string }` (OAuth-style).

---

## Ejemplo completo (pseudo-código)

```typescript
// Paso 1: obtener la clave JWE
const { data: jwk } = await fetch('https://aegis.example.com/api/v1/auth/encryption-key').then(r => r.json());

// Paso 2: armar el payload del JWE
const iat = Math.floor(Date.now() / 1000);
const jti = crypto.randomUUID();

const jwePayload = {
  clientId: 'aegis-AEGIS-DEMO-e8a6cb',
  userData: {
    username: 'user-demo-001',
    email: 'user-demo-001@example.com',
    password: 'Jorge#asd12asdfasdf'
  },
  credentials: {
    user_check: 'user-demo-001'  // ← igual a user_identifier del outer
  },
  anti_replay: { iat, jti }
};

// Paso 3: cifrar con jose
const jwe = await new jose.CompactEncrypt(
  new TextEncoder().encode(JSON.stringify(jwePayload))
)
  .setProtectedHeader({ alg: jwk.alg, enc: 'A256GCM' })
  .encrypt(await jose.importJWK(jwk, jwk.alg));

// Paso 4: enviar la request
const response = await fetch('https://aegis.example.com/api/v1/co/public/user', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    user_identifier: 'user-demo-001',  // ← igual a credentials.user_check
    secure_payload: jwe
  })
});

// 201 → usuario creado
// 409 → ya existe
// 400/401 → error de validación
```

---

## Resumen de reglas críticas

1. **`user_identifier` del outer body** y **`credentials.user_check` del JWE** deben ser **exactamente el mismo string**. Si difieren → 400.

2. **`anti_replay.jti`** debe ser **único por cada request**. Si reusás el mismo jti antes de que expire la ventana de validez → 401 replay detected. aegis-core cachea los jti en Redis.

3. **`anti_replay.iat`** debe estar **dentro de la ventana de validez** del server (centrado en `now` con un clock skew). Si es muy viejo (clock skew expirado) o muy futuro (clock del client desincronizado) → 401.

4. **`secure_payload`** es un JWE compact serialization. Algoritmos aceptados: `RSA-OAEP-256` o `ECDH-ES+A256KW` para el key encryption, `A256GCM` para el content encryption.

5. **`clientId`** es el Keycloak OAuth client id (string), no un UUID. Se reenvía tal cual a aegis-admin.

6. **`device_context`** es completamente opcional. Si lo mandás, tiene que ser un objeto. El server **no** lee ni valida sus campos internos — se ignora.

7. **No hay autenticación previa**. Es endpoint público. El rate limit es la única protección contra abuso.

---

## Lo que NO se puede deducir del código

- **Valores exactos del rate limit** (cuántas requests por ventana): son configurables vía env vars, no están hardcodeados.
- **Ventana exacta del anti_replay** (cuánto dura un jti en Redis, cuánto clock skew se tolera): configurable vía env vars.
- **Política exacta de password** que aplica aegis-admin: vive en aegis-admin, no en aegis-core.

---

## Conceptos clave para entender todo

### 1. `iat` y `jti` — el anti-replay

Son dos campos que juntos evitan que alguien **reuse la misma request** más de una vez. Son estándar de JWT (`iat` = "issued at", `jti` = "JWT ID").

**`iat` (issued at)** — "esto se emitió en este momento"

- Es un **timestamp Unix en SEGUNDOS** (no milisegundos)
- `Math.floor(Date.now() / 1000)` te da un número como `1773670282`
- Eso equivale a `2026-06-16 14:11:22 UTC`
- El server valida que esté **dentro de una ventana de tiempo** (ej: últimos 300s). Si está muy viejo o muy futuro → 401
- **Por qué**: si alguien intercepta tu request, no puede reusarla después porque el `iat` ya estará vencido

**`jti` (JWT ID)** — "ID único de esta request"

- Es un **UUID v4 aleatorio** generado por el cliente
- `crypto.randomUUID()` te da algo como `550e8400-e29b-41d4-a716-446655440000`
- El server **guarda cada jti en Redis** con TTL (default 300s)
- Si alguien manda otra request con el **mismo jti** → 401 "replay detected"
- **Por qué**: el `iat` solo no alcanza — alguien podría mandar 100 requests en el mismo segundo con el mismo `iat`. El `jti` garantiza unicidad incluso al milisegundo

**Juntos**: `iat` dice **cuándo**, `jti` dice **cuál**. Los dos van dentro del campo `anti_replay` del JWE.

### 2. Por qué se cifra (JWE)

Tu payload tiene datos sensibles: `password`, `clientId`. Si los mandás en plaintext, cualquiera que intercepte la request (sin HTTPS, proxy MITM, logs del server) los ve.

**JWE (JSON Web Encryption)** cifra los datos con la **clave pública** del server. Funciona como un candado:

1. El server te da una **clave pública** (el candado abierto)
2. Vos **cifrás** tus datos con ese candado
3. Mandás los datos cifrados
4. **Solo el server** (que tiene la clave privada) puede descifrar

Vos **nunca** ves la clave privada. Solo podés cifrar, no descifrar.

**El JWE compact serialization** es un string con 5 segmentos base64url joined por `.`:

```
<header>.<encryptedKey>.<iv>.<ciphertext>.<authTag>
```

Ejemplo: `eyJhbGciOiJSU0EtT0FFUC0yNTYi...K.OH8K9fN0k7p2M1x4...`

- **Header** (JSON): metadata del cifrado (`alg`, `enc`)
- **encryptedKey**: la clave AES cifrada con la pública RSA
- **iv**: vector de inicialización para AES-GCM
- **ciphertext**: tus datos cifrados
- **authTag**: tag de autenticación (detecta tampering)

Con la librería `jose` todo esto es transparente:

```typescript
const jwe = await new CompactEncrypt(
  new TextEncoder().encode(JSON.stringify(payload))
)
  .setProtectedHeader({ alg: jwk.alg, enc: 'A256GCM' })
  .encrypt(key);  // key = la clave pública importada
```

### 3. El JWK (clave pública) — qué significa cada campo

Cuando hacés `GET /api/v1/auth/encryption-key`, recibís:

```json
{
  "data": {
    "kty": "RSA",
    "n": "0Z0VS5JJcds3xfNNXokG...",
    "e": "AQAB",
    "kid": "xJ3yK2nP5qR8sT1uV4wX",
    "use": "enc",
    "alg": "RSA-OAEP-256"
  }
}
```

| Campo | Significado | Para qué lo usás |
|---|---|---|
| `kty` | Key Type — `RSA` o `EC` | La librería sabe qué tipo de clave es |
| `n` | Modulus RSA (clave pública, en base64url) | La librería lo usa para cifrar. Es la "matemática" del candado |
| `e` | Exponente RSA (casi siempre `AQAB` = 65537) | Combinado con `n` para hacer la operación de cifrado |
| `kid` | Key ID — identificador único de esta clave | Por si el server rota claves en el futuro. Hoy siempre es la misma |
| `use` | Uso declarado — `enc` = encryption | Confirma que esta clave es para cifrar (no para firmar) |
| `alg` | Algoritmo de cifrado | **Este es el que usás**: `importJWK(jwk, jwk.alg)` le dice a la librería cómo usar esta clave |

**No necesitás entender la matemática RSA**. La librería `jose` lo hace. Solo necesitás:

```typescript
const key = await importJWK(jwk, jwk.alg);  // convierte el JWK a un objeto CryptoKey
// Ahora usás `key` directamente para cifrar
const jwe = await new CompactEncrypt(data).setProtectedHeader({...}).encrypt(key);
```

`jose` usa `jwk.n + jwk.e` para construir la clave pública RSA, y aplica `jwk.alg` como algoritmo de cifrado. Todo automático.
