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

## 4. Validación DPoP (Tab 5 — Casos 1 a 6)

| Caso | Botón | Esperado |
|------|-------|----------|
| 1 | Token y DPoP válidos | HTTP 200 en `/users/me` |
| 2 | Phantom + DPoP diferente | HTTP 401 |
| 3 | DPoP alterado | HTTP 401 |
| 4 | Phantom Token inválido | HTTP 401 |
| 5 | Logout con DPoP inválido | Sesión no revocada |
| 6 | Introspect token inválido | `active: false` |

Pre-requisito: tabs 1 y 2 completados.

## 5. Modo Test de Seguridad (Tab 5)

| Botón | Esperado |
|-------|----------|
| Login válido | HTTP 200 + Phantom tokens |
| Login con DPoP alterado | HTTP 401 |
| Logout con DPoP alterado | Sesión no revocada |
| Introspect con token inválido | `active: false` |
| Introspect con token expirado | `active: false` (tras `expires_in`) |

## 6. Evidencia visual

Capturar pantalla del panel **Aegis response** para cada escenario exitoso y fallido (HTTP status + JSON + trace).
