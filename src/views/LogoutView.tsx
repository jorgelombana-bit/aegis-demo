import { useState } from 'react';

import { RequestPreview } from '../components/RequestPreview';
import { useSessionState } from '../hooks/useSessionState';
import { actionLogout, type ActionResult } from '../lib/actions';
import { htuForAegis } from '../lib/dpop';
import { getDpopKeyPair, getDpopPublicJwk } from '../lib/session';

type Props = {
  onResult: (result: ActionResult<unknown> | null) => void;
  onLoadingChange?: (loading: boolean) => void;
  result: ActionResult<unknown> | null;
};

export function LogoutView({ onResult, onLoadingChange, result }: Props) {
  const session = useSessionState();
  const [loading, setLoading] = useState(false);
  // Hooks must be called in the same order every render; compute these BEFORE
  // any early return so Rules of Hooks is happy.
  const url = session ? htuForAegis(`/api/v1/${session.country}/public/logout`) : '';
  const dpopKeyPair = getDpopKeyPair();
  const dpopPublicJwk = getDpopPublicJwk();
  const jkt = dpopKeyPair?.jkt ?? '<no keypair>';
  const jti = '<UUID v4, generado al submit>';

  if (!session || !session.accessToken) {
    return (
      <div className="empty-state">
        <p>No active phantom session.</p>
        <p className="muted">Run the Login tab first to obtain a Phantom access token.</p>
      </div>
    );
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    onLoadingChange?.(true);
    onResult(null);
    const res = await actionLogout();
    onResult(res);
    setLoading(false);
    onLoadingChange?.(false);
  };

  return (
    <form onSubmit={submit} className="form">
      <div className="kv">
        <table>
          <tbody>
            <tr><th>User</th><td>{session.username}</td></tr>
            <tr><th>Channel clientId</th><td className="mono">{session.channelId}</td></tr>
            <tr><th>Phantom access_token</th><td className="mono">{session.accessToken}</td></tr>
            <tr><th>Phantom refresh_token</th><td className="mono">{session.refreshToken}</td></tr>
            <tr><th>DPoP jkt</th><td className="mono">{session.dpopJkt}</td></tr>
            <tr><th>DPoP jkt will be sent as</th><td className="mono">{jkt}</td></tr>
            <tr><th>DPoP proof jti (anti-replay)</th><td className="mono">{jti}</td></tr>
          </tbody>
        </table>
      </div>

      <RequestPreview
        title="Request completo — click para ver"
        method="POST"
        url={url}
        headers={[
          { name: 'Authorization', value: 'Bearer ' + session.accessToken },
          { name: 'Content-Type', value: 'application/json' },
          { name: 'DPoP', value: '<raw compact jwt>  (header.typ=dpop+jwt, alg=ES256, jkt=' + jkt + ', con ath)' },
        ]}
        dpopProof={{
          header: {
            typ: 'dpop+jwt',
            alg: 'ES256',
            jwk: dpopPublicJwk ?? { kty: 'EC', crv: 'P-256', x: '<...>', y: '<...>' },
          },
          payload: {
            htm: 'POST',
            htu: url,
            iat: '<unix-seconds>',
            jti,
            ath: 'base64url(sha256(<phantom_access_token>))',
            jkt,
          },
          wireFormat: '<header-base64url>.<payload-base64url>.<signature-base64url>',
        }}
        rawBody={{ refresh_token: session.refreshToken }}
        rawBodyBytes={JSON.stringify({ refresh_token: session.refreshToken }, null, 2)}
        why={[
          { q: '¿Por qué "Authorization: Bearer" (no DPoP)?', a: 'El handler de logout llama a `extractBearerTokenFromRequest(request)`, que exige scheme = "Bearer" case-insensitive. Si envías "DPoP" el handler responde 401 "Bearer phantom access token is required".' },
          { q: '¿Por qué el header DPoP es el JWT crudo (sin prefijo "DPoP ")?', a: 'El guard manual dentro del handler es DpopAuthGuard (no DpopLoginGuard). DpopAuthGuard lee `request.headers["dpop"]` directamente y espera el compact JWT sin prefijo.' },
          { q: '¿Por qué ath en la prueba?', a: 'ath = base64url(sha256(access_token)) es obligatorio para DpopAuthGuard. Sin él, el guard lanza UnauthorizedException("DPOP_ATH_MISMATCH").' },
          { q: '¿Por qué el body es solo { refresh_token }?', a: 'El DTO `PublicHumanLogoutRequestDto` (en aegis-core) sólo valida ese campo. La versión anterior usaba JWE envelope; la nueva sólo requiere el refresh_token en claro. El handler resuelve el resto desde Redis.' },
          { q: '¿Por qué "DPoP sin prefijo" pero con jkt?', a: 'El DpopAuthGuard computa jkt del header.jwk y lo compara con `accessSession.dpop_jkt` de Redis. Si difieren (escenario de tampering), el guard falla → 401.' },
          { q: '¿Por qué el handler responde siempre 204?', a: 'El controller `publicHumanLogout` envuelve toda la lógica en try/catch y devuelve `ThResponseBuilder.noContent(null)` en cualquier error. La respuesta HTTP no indica éxito; hay que verificar con introspect o /users/me que la sesión realmente fue revocada.' },
        ]}
        aegisValidates={[
          'RateLimiterGuard: 10 req / 60 s, identifierType=USER_ID (prefix RATE_LIMIT_PHANTOM_USER_ID)',
          'DpopAuthGuard (manual call dentro del handler, NO DpopLoginGuard):',
          '  · header.typ === "dpop+jwt"',
          '  · header.alg ∈ {ES256, RS256, PS256}',
          '  · header.jwk presente',
          '  · payload.htm === "POST"',
          '  · payload.htu === buildDpopTargetUri(request)',
          '  · payload.iat dentro de 300s',
          '  · payload.jti es UUID v4 (anti-replay en Redis key dpop:jti:<userId>:<jti>, TTL 5 min)',
          '  · payload.ath === base64url(sha256(access_token))',
          '  · jkt(header.jwk) === accessSession.dpop_jkt (vínculo Phantom↔DPoP)',
          'extractBearerTokenFromRequest: scheme === "Bearer" (no DPoP)',
          'Body: { refresh_token: <UUID v4> } — validado por PublicHumanLogoutRequestDto',
          'PublicHumanLogoutHandler.assertLogoutSessionsMatch:',
          '  ① accessSession.sessionId === refreshSession.sessionId',
          '  ② refreshSession.accessTokenHash === sha256(phantom_access_token)',
          '  ③ accessSession.dpopJkt === refreshSession.dpopJkt',
          '  ④ accessSession.dpopJkt === dpopJkt_del_proof  (vínculo final)',
          'Keycloak revoke: POST /realms/{realm}/protocol/openid-connect/logout con refresh_token',
          'Redis delete: session:access:<sha256(access)>, session:refresh:<sha256(refresh)>',
          'Respuestas: 204 No Content (idempotent, incluso en error)',
        ]}
        expectedHttp="204 No Content"
        expectedBody="(vacío) — verificar con introspect que la sesión quedó revocada"
      />

      <button type="submit" disabled={loading} className="btn-primary">
        {loading ? 'Logging out…' : 'Logout (revoke phantom + Keycloak refresh)'}
      </button>
      {loading && <p className="muted">Building DPoP proof with ath, posting to aegis-core, verifying session was revoked…</p>}
      {!loading && result && (
        <p className="muted small">
          Última respuesta: HTTP {result.httpStatus ?? '?'} —{' '}
          {result.ok ? 'logout procesado (204). Verifica con introspect que la sesión quedó revocada.' : `falló (${result.error ?? 'sin mensaje'})`}.{' '}
          Para detalles completos, mira el panel "Aegis response" a la derecha.
        </p>
      )}
    </form>
  );
}
