import { useState } from 'react';

import { RequestPreview } from '../components/RequestPreview';
import { actionLogin, type ActionResult } from '../lib/actions';
import { htuForAegis } from '../lib/dpop';
import { getDpopKeyPair, getDpopPublicJwk } from '../lib/session';

type Props = {
  defaultCountry: string;
  defaultOauthClientId: string;
  onResult: (result: ActionResult<unknown> | null) => void;
  onLoadingChange?: (loading: boolean) => void;
  result: ActionResult<unknown> | null;
};

const DPOP_ALG = 'ES256' as const;

export function LoginView({ defaultCountry, defaultOauthClientId, onResult, onLoadingChange, result }: Props) {
  const [country, setCountry] = useState(defaultCountry);
  const [oauthClientId, setOauthClientId] = useState(defaultOauthClientId);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    onLoadingChange?.(true);
    onResult(null);
    const res = await actionLogin({ country, clientId: oauthClientId, username, password, alg: DPOP_ALG });
    onResult(res);
    setLoading(false);
    onLoadingChange?.(false);
  };

  const url = htuForAegis(`/api/v1/${country || 'co'}/public/login`);
  const dpopKeyPair = getDpopKeyPair();
  const dpopPublicJwk = getDpopPublicJwk();
  const jkt = dpopKeyPair?.jkt ?? '<compute-on-first-login>';

  return (
    <form onSubmit={submit} className="form">
      <div className="field-row">
        <div className="field">
          <label>Country (ISO-2)</label>
          <input value={country} onChange={(e) => setCountry(e.target.value)} maxLength={2} required />
          <small className="muted">Realm: <code>puntored-{'{country}'}</code>.</small>
        </div>
        <div className="field">
          <label>Channel clientId</label>
          <input
            value={oauthClientId}
            onChange={(e) => setOauthClientId(e.target.value)}
            required
          />
          <small className="muted">
            Keycloak OAuth/OIDC client identifier del usuario (p. ej. <code>aegis-AEGIS-DEMO-e8a6cb</code>).
            aegis-core lo usa para resolver el realm y para validar membresía vía aegis-admin (gRPC).
            NO es el UUID del canal.
          </small>
        </div>
      </div>
      <div className="field-row">
        <div className="field">
          <label>Username / Email</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)} required />
        </div>
        <div className="field">
          <label>Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
      </div>

      <RequestPreview
        title="Request completo — click para ver"
        method="POST"
        url={url}
        headers={[
          { name: 'Content-Type', value: 'application/json' },
          { name: 'DPoP', value: 'DPoP <compact-jwt>  (header.typ=dpop+jwt, alg=' + DPOP_ALG + ', jkt=' + jkt + ')' },
        ]}
        dpopProof={{
          header: {
            typ: 'dpop+jwt',
            alg: DPOP_ALG,
            jwk: dpopPublicJwk ?? {
              kty: 'EC', crv: 'P-256', x: '<generated-on-first-login>', y: '<generated-on-first-login>',
            },
          },
          payload: {
            htm: 'POST',
            htu: url,
            iat: '<unix-seconds>',
            jti: '<UUID v4>',
            jkt,
          },
          wireFormat: '<header-base64url>.<payload-base64url>.<signature-base64url>',
        }}
        jweBody={{
          encrypted:
            'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.<cek>.<iv>.<tag>  (RSA-OAEP-256 / A256GCM, computed on click)',
          plaintextShape: {
            credentials: {
              clientId: oauthClientId || '<Keycloak OAuth clientId>',
              pass: password ? '*'.repeat(password.length) : '<password>',
              user_check: username || '<username>',
            },
            anti_replay: { iat: '<unix-seconds, generado al submit>', jti: '<UUID v4, generado al submit>' },
          },
        }}
        why={[
          { q: '¿Por qué JWE en credenciales?', a: 'credentials.pass y clientId son sensibles. Se encriptan con la clave pública RSA-OAEP-256 (o ECDH-ES) que aegis-core expone en GET /api/v1/auth/encryption-key. Sólo aegis-core puede descifrar.' },
          { q: '¿Por qué DPoP?', a: 'DpopLoginGuard exige una prueba DPoP firmada con una clave del browser. La jkt de la prueba (thumbprint del JWK público en el header) se persiste en la sesión phantom como vínculo de seguridad — luego /users/me y logout comparan contra ella.' },
          { q: '¿Por qué "DPoP <jwt>" con prefijo en el header?', a: 'El DpopLoginGuard hace `dpopHeader.slice("DPoP ".length)` para extraer el JWT. Sin el prefijo literal, lanza DPOP_AUTH_SCHEME_MISMATCH. (Otros guards como DpopAuthGuard en /users/me esperan el JWT crudo sin prefijo.)' },
          { q: '¿Por qué la prueba NO incluye ath?', a: 'ath = base64url(sha256(access_token)) sólo aplica cuando ya hay un access_token (endpoints protegidos con DpopAuthGuard: /users/me, /auth/refresh-token). En login aún no hay access_token.' },
          { q: '¿Por qué user_identifier === credentials.user_check?', a: 'El UserCheckGuard exige esta igualdad para detectar payloads manipulados. Si difieren, el guard lanza UserCheckMismatchException → 401.' },
          { q: '¿Por qué credentials.clientId es el Keycloak clientId y NO el UUID del canal?', a: 'Desde SJ-267 el login hace password grant contra Keycloak usando este clientId y luego valida membresía user↔client vía gRPC aegis-admin (forgotPassword). El "channel UUID" de aegis-admin se mapea internamente y se almacena como channelId en la sesión phantom; el cliente ya no lo envía explícitamente en el login.' },
          { q: '¿Por qué anti_replay (iat + jti)?', a: 'Cada intento de login lleva un jti único (UUID v4) + iat dentro de 300s. aegis-core cachea el jti en Redis con TTL 5 min; si se reusa, AntiReplayRejectedException → 401. Esto previene replay attacks.' },
        ]}
        aegisValidates={[
          'RateLimiterGuard: 10 req / 60 s (prefix RATE_LIMIT_PUBLIC_HUMAN_LOGIN)',
          'JweDecryptInterceptor: descifra secure_payload → JSON',
          'user_identifier === credentials.user_check (UserCheckGuard)',
          'credentials.clientId es un string no vacío (Keycloak OAuth clientId; no se valida como UUID)',
          'AntiReplayGuard: iat dentro de 300s ± 30s; jti es UUID v4; jti no usado en Redis (TTL 5 min)',
          'DpopLoginGuard:',
          '  · header.typ === "dpop+jwt"',
          '  · header.alg ∈ {ES256, RS256, PS256}',
          '  · header.jwk presente (la clave pública del browser)',
          '  · payload.htm === "POST" (método del request)',
          '  · payload.htu === buildDpopTargetUri(request) (URL completa con scheme + host + path)',
          '  · payload.iat dentro de 300s',
          '  · payload.jti es UUID v4 (DpopLoginGuard NO valida anti-replay del jti; eso es del DpopAuthGuard)',
          'AegisAdminUserClientMembershipService.userBelongsToClient: gRPC aegis-admin.forgotPassword({userIdentifier, clientId}) — si devuelve id vacío lanza 401 USER_CLIENT_MISMATCH',
          'PublicHumanLoginHandler: llama a Keycloak password grant con clientId resuelto',
          'PhantomSessionService: persiste sesión AES-256-GCM en Redis',
          '  · key session:access:<sha256(access_token)>',
          '  · key session:refresh:<sha256(refresh_token)>',
          '  · TTL = expires_in (típicamente 900s = 15 min)',
          '  · payload.session = { dpop_jkt, sub, country, clientId, channelId, roles, iat, exp }',
          'Respuestas: 200 (phantom tokens) · 400 (DTO inválido) · 401 (credenciales / DPoP / anti-replay / user_client_mismatch) · 429 · 502 (Keycloak no disponible)',
        ]}
        expectedHttp="200 OK"
        expectedBody='{ access_token, refresh_token, expires_in, token_type: "DPoP" } (ambos UUID v4)'
      />

      <button type="submit" disabled={loading || !oauthClientId.trim()} className="btn-primary">
        {loading ? 'Logging in…' : 'Login (Phantom Token + DPoP)'}
      </button>
      {loading && <p className="muted">Building DPoP proof, encrypting JWE, posting to aegis-core…</p>}
      {!loading && result && (
        <p className="muted small">
          Última respuesta: HTTP {result.httpStatus ?? '?'} —{' '}
          {result.ok ? 'éxito (phantom tokens guardados)' : `falló (${result.error ?? 'sin mensaje'})`}.{' '}
          Para detalles completos, mira el panel "Aegis response" a la derecha.
        </p>
      )}
    </form>
  );
}
