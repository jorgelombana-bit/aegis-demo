# aegis-demo

Demo UI para los flujos de seguridad de **Aegis Core**:

1. **Create User** — `POST /api/v1/{country}/public/user`
2. **Login** — Phantom Token + DPoP + Rate Limit
3. **Logout** — Phantom Token + DPoP + Rate Limit
4. **Introspect** — Internal API Guard
5. **Security Test** — Casos DPoP 1–6 + Modo Test de Seguridad

La UI consume `aegis-core` vía proxy de Vite. Cifrado JWE y DPoP en el navegador (`jose` + WebCrypto).

## Quick start

```bash
pnpm install
cp .env.example .env
# VITE_AEGIS_INTERNAL_API_KEY=<valor de aegis-core INTERNAL_API_KEY>
pnpm dev
```

## Variables de entorno

| Variable | Default | Requerida |
|---|---|---|
| `VITE_AEGIS_INTERNAL_API_KEY` | vacío | Sí (introspect) |
| `VITE_AEGIS_PROXY_TARGET` | `https://aegis-dev.preprodcxr.co` | No |
| `VITE_AEGIS_PUBLIC_ORIGIN` | igual al target | No |
| `VITE_DEFAULT_COUNTRY` | `co` | No |
| `VITE_DEFAULT_CHANNEL_ID` | `f51bc49c-50f6-477d-873e-2408fff7746e` | No |

## Documentación de pruebas

Ver [`DEMO_GUIDE.md`](./DEMO_GUIDE.md).
