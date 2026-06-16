import { useEffect, useState } from 'react';

import { RequestPreview } from '../components/RequestPreview';
import { useSessionState } from '../hooks/useSessionState';
import { actionIntrospect, type ActionResult } from '../lib/actions';

type Props = {
  onResult: (result: ActionResult<unknown> | null) => void;
  onLoadingChange?: (loading: boolean) => void;
  result: ActionResult<unknown> | null;
};

const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function IntrospectView({ onResult, onLoadingChange, result }: Props) {
  const session = useSessionState();
  const [token, setToken] = useState(session?.accessToken ?? '');
  const [loading, setLoading] = useState(false);

  // Re-sync the input when the session changes (e.g. after login or logout).
  // We can't use a derived value because the user must be able to edit the input.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (session?.accessToken) setToken(session.accessToken);
  }, [session?.accessToken]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    onLoadingChange?.(true);
    onResult(null);
    const res = await actionIntrospect({ token: token.trim() });
    onResult(res);
    setLoading(false);
    onLoadingChange?.(false);
  };

  const isValid = UUID_V4_REGEX.test(token.trim());
  const url = '/internal/token/introspect  (Vite proxy → /api/v1/internal/token/introspect)';

  return (
    <form onSubmit={submit} className="form">
      <div className="field">
        <label>Phantom access token (UUID v4)</label>
        <input
          value={token}
          onChange={(e) => setToken(e.target.value)}
          required
          className={`mono ${isValid ? '' : 'invalid'}`}
        />
        <small className={isValid ? 'muted' : 'muted warn'}>
          {isValid
            ? 'UUID v4 válido. Por defecto es el access_token de la sesión activa.'
            : 'Debe ser un UUID v4 (formato: 550e8400-e29b-41d4-a716-446655440000).'}
        </small>
      </div>

      <RequestPreview
        title="Request completo — click para ver"
        method="POST"
        url={url}
        headers={[
          { name: 'X-Internal-API-Key', value: '<server-side, inyectado por el Vite proxy desde VITE_AEGIS_INTERNAL_API_KEY>' },
          { name: 'X-Caller-Service', value: 'aegis-demo-ui  (audit-trace identifier)' },
          { name: 'Content-Type', value: 'application/json' },
        ]}
        rawBody={{ token: token.trim() || '<UUID v4>' }}
        rawBodyBytes={JSON.stringify({ token: token.trim() || '<UUID v4>' }, null, 2)}
        why={[
          { q: '¿Por qué X-Internal-API-Key en lugar de JWT?', a: 'El endpoint está protegido por InternalApiAuthGuard, que compara el header contra `envs.internalApiKey` de aegis-core. NO usa JWT porque es un endpoint de servicio-a-servicio (introspection), no de usuario final. La clave se inyecta server-side en el Vite proxy para no exponerla al browser.' },
          { q: '¿Por qué X-Caller-Service?', a: 'Auditoría. aegis-core emite eventos `INTROSPECTION_REQUEST` y `TOKEN_INTROSPECTION_FAILURE` a Kafka con este header como actor. Default: "internal-service".' },
          { q: '¿Por qué no hay DPoP?', a: 'El InternalApiAuthGuard NO es un DpopAuthGuard. La auth es por shared secret (X-Internal-API-Key), no por prueba criptográfica. Es un endpoint de backend, no de usuario.' },
          { q: '¿Por qué { token: "..." } como body, no como query param?', a: 'RFC 7662 §2.1 define el request como POST con `application/x-www-form-urlencoded` o JSON con { token }. aegis-core acepta ambos; este cliente usa JSON por consistencia.' },
          { q: '¿Por qué la respuesta es siempre HTTP 200 (incluso para token inválido)?', a: 'RFC 7662 §2.2: "If the introspection call is properly authorized but the token is not active, does not exist on this server, or the protected resource is not allowed to introspect this particular token, then the authorization server MUST return an introspection response with the `active` field set to `false`."' },
          { q: '¿Cómo verifico el vínculo Phantom↔DPoP desde introspect?', a: 'Si active=true, el body incluye `dpop_jkt`. Compara ese valor con el `dpopJkt` del banner de sesión: deben ser idénticos.' },
        ]}
        aegisValidates={[
          'InternalApiAuthGuard: X-Internal-API-Key === envs.internalApiKey  (inyectado por el Vite proxy)',
          'Body: { token } — token debe ser UUID v4',
          'ResolveAccessSessionPort: lookup Redis key session:access:<sha256(token)>',
          'Si la sesión existe y no expiró:',
          '  · return { active: true, sub, country, client_id, roles, dpop_jkt, iat, exp }',
          'Si la sesión no existe, expiró o está corrupta:',
          '  · return { active: false }  (HTTP 200 igualmente)',
          'Errores:',
          '  · 400 si el token no es UUID v4',
          '  · 401 si X-Internal-API-Key falta o es inválido',
        ]}
        expectedHttp="200 OK"
        expectedBody='{ active: true, sub, country, client_id, roles, dpop_jkt, iat, exp }   O   { active: false }'
      />

      <button type="submit" disabled={loading || !isValid} className="btn-primary">
        {loading ? 'Introspecting…' : 'Introspect (Internal API Guard)'}
      </button>
      {loading && <p className="muted">Calling Internal API through Vite proxy (X-Internal-API-Key injected server-side)…</p>}
      {!loading && result && (
        <p className="muted small">
          Última respuesta: HTTP {result.httpStatus ?? '?'} —{' '}
          {result.ok ? 'token activo' : `token NO activo (${result.error ?? 'active:false'})`}.{' '}
          Para detalles completos, mira el panel "Aegis response" a la derecha.
        </p>
      )}
    </form>
  );
}
