# Guía de ejecución de pruebas — Aegis Demo UI

## 1. Setup

```bash
cd AEGIS-DEMO
pnpm install
cp .env.example .env
# VITE_AEGIS_INTERNAL_API_KEY=<INTERNAL_API_KEY de aegis-core>
pnpm dev
```

## 2. Pestañas

| Pestaña | Flujo |
|---------|-------|
| 1. Create User | Registro público (JWE) |
| 2. Login | Phantom Token + DPoP |
| 3. Logout | Phantom Token + DPoP |
| 4. Introspect | Internal API Guard |
| 5. Security Test | Casos DPoP + Modo Test |

## 3. Flujos principales

### Create User
1. Completar country, channel clientId (`data.id`), username, email, password.
2. Click **Create User** → esperar HTTP 201.

### Login
1. Credenciales del usuario creado.
2. Click **Login** → HTTP 200 con `access_token`, `refresh_token`, `token_type: DPoP`.

### Logout
1. Con sesión activa, click **Logout** → HTTP 204.

### Introspect
1. Pegar phantom `access_token`.
2. Click **Introspect** → HTTP 200 con respuesta completa.
3. Verificar vínculo **Phantom↔DPoP**: `dpop_jkt` de la respuesta = `jkt` del banner de sesión.

## 4. Security Test (Tab 5) — 5 escenarios con request preview completo

La Tab 5 es la vista "Modo Test de Seguridad". Cada botón es una **tarjeta
expandible** que muestra, antes de ejecutar la llamada, todo lo que se enviará
y todo lo que validará aegis-core. Click en **Ejecutar escenario** dispara
la request real; la respuesta aparece en el panel **Aegis response** de la derecha.

| # | Card | Caso task | Endpoint | Esperado |
|---|------|-----------|----------|----------|
| 1 | Login válido (Phantom + DPoP correctos)         | Caso 1 | `POST /api/v1/{country}/public/login`    | 200 + phantom tokens |
| 2 | Login con DPoP alterado (htu falsificado)       | Caso 3 | `POST /api/v1/{country}/public/login`    | 401 `DPOP_HTU_MISMATCH` |
| 3 | Logout con DPoP inválido (jkt distinto)          | Caso 5 | `POST /api/v1/{country}/public/logout`   | 401 Phantom session mismatch |
| 4 | Introspect con token inválido (UUID sin sesión)  | Caso 6 | `POST /internal/token/introspect`        | 200 `{ active: false }` |
| 5 | Introspect con token expirado                    | Caso 4 | `POST /internal/token/introspect`        | 200 `{ active: false }` tras Redis TTL |

> **Cada card muestra explícitamente**:
> 1. El método y URL exactos.
> 2. Los headers HTTP completos (Authorization, DPoP, X-Internal-API-Key, etc.).
> 3. La estructura del **DPoP proof** (header + payload, con `jkt` actual).
> 4. El cuerpo de la request — JSON puro o el **JWE envelope** (texto plano
>    legible que aegis-core descifrará, más los primeros 40 chars del JWE
>    compact encriptado que viaja en la red).
> 5. La **cadena de validaciones** que aegis-core ejecuta (JWE decrypt,
>    AntiReplayGuard, DpopLoginGuard/AuthGuard, PhantomTokenGuard, etc.).
> 6. La respuesta esperada (HTTP + body shape).
> 7. El badge `coincide / no coincide con lo esperado` después de ejecutar.

### Caso 2 (Phantom + DPoP diferente sobre endpoint protegido)

No es un botón directo; se verifica combinando:
1. Click en el botón **1. Login válido** de la Tab 5 (obtiene sesión válida).
2. La sesión se cachea; el `dpopJkt` se muestra en el banner superior.
3. Cualquier llamada posterior con un DPoP keypair fresco (que un atacante
   fabricaría) será rechazada con 401 `DPOP_JKT_MISMATCH`. El botón **3.
   Logout con DPoP inválido** de la Tab 5 ejercita exactamente este flujo
   contra el endpoint de logout.

## 5. Pre-requisitos generales

- Tab **1. Create User** y Tab **2. Login** ejecutadas al menos una vez.
- Para el escenario 5 (token expirado): esperar a que el `expires_in` del login
  llegue a 0 (típicamente 300s). La card 5 muestra el contador en vivo.

## 6. Evidencia visual

Capturar pantalla del panel **Aegis response** para cada escenario exitoso y fallido (HTTP status + JSON + trace).
