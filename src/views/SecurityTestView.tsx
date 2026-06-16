import { useEffect, useState } from 'react';

import { KeyValueTable } from '../components/KeyValueTable';
import { JsonView } from '../components/JsonView';
import { actionIntrospect, actionLogin, type ActionResult } from '../lib/actions';
import { htuForAegis } from '../lib/dpop';
import { getDpopKeyPair, getDpopPublicJwk, getSession, getStoredPassword } from '../lib/session';
import { runLogoutWithWrongDpop, INVALID_PHANTOM_UUID } from '../lib/security-runners';

type Props = {
  onResult: (result: ActionResult<unknown> | null) => void;
  onLoadingChange?: (loading: boolean) => void;
  result: ActionResult<unknown> | null;
};

type Outcome = 'accept' | 'reject';

type Scenario = {
  key: string;
  title: string;
  /** One-line summary shown in the collapsed card. */
  summary: string;
  outcome: Outcome;
  expectedHttp: string;
  expectedBodyShape: string;
  casesCovered: string[];
  renderRequest: () => {
    method: string;
    url: string;
    headers: Array<{ name: string; value: string }>;
    dpopProof?: {
      header: Record<string, unknown>;
      payload: Record<string, unknown>;
      wireFormat: string;
    };
    jweBody?: {
      encrypted: string;
      plaintextShape: Record<string, unknown>;
    };
    rawBody?: Record<string, unknown>;
    rawBodyBytes?: string;
    aegisValidates: string[];
  };
  requiresSession?: boolean;
  runner: () => Promise<ActionResult<unknown>>;
};

function scenarioPassed(result: ActionResult<unknown>, scenario: Scenario): boolean {
  if (scenario.outcome === 'accept') return result.ok;
  return !result.ok;
}

export function SecurityTestView({ onResult, onLoadingChange, result }: Props) {
  const [loading, setLoading] = useState<string | null>(null);
  const [lastResults, setLastResults] = useState<Record<string, boolean>>({});
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [now, setNow] = useState(() => Date.now());
  // Re-render every second so the "expires in" countdown stays live.
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const session = getSession();
  const password = getStoredPassword();
  const dpopKeyPair = getDpopKeyPair();
  const dpopPublicJwk = getDpopPublicJwk();

  const scenarios = buildScenarios({ session, password, dpopKeyPair, dpopPublicJwk, now });

  const run = async (scenario: Scenario) => {
    if (scenario.requiresSession && (!session?.accessToken || !session.refreshToken)) {
      onResult({
        ok: false,
        error: 'Necesitas iniciar sesión en la pestaña 2 (Login) antes de ejecutar este escenario.',
        log: [],
      });
      return;
    }
    setLoading(scenario.key);
    onLoadingChange?.(true);
    onResult(null);
    const res = await scenario.runner();
    const passed = scenarioPassed(res, scenario);
    setLastResults((prev) => ({ ...prev, [scenario.key]: passed }));
    onResult(res);
    setLoading(null);
    onLoadingChange?.(false);
  };

  const toggleExpand = (key: string) => {
    setExpanded((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  return (
    <div className="security-test">
      <header className="security-intro">
        <p className="muted small">
          5 escenarios one-click para validar el comportamiento del mecanismo DPoP.
          Cada card muestra el resultado esperado de un vistazo; hace click en{' '}
          <em>Ver request completo</em> para ver headers, DPoP proof, JWE body y las
          validaciones que ejecutará aegis-core.
        </p>
        <p className="muted small">
          Pre-requisito general: haber corrido la pestaña <strong>1. Create User</strong> y
          la pestaña <strong>2. Login</strong> al menos una vez.
        </p>
      </header>

      <div className="security-grid">
        {scenarios.map((s) => (
          <ScenarioCard
            key={s.key}
            scenario={s}
            loading={loading === s.key}
            passed={lastResults[s.key]}
            isExpanded={!!expanded[s.key]}
            onToggleExpand={() => toggleExpand(s.key)}
            onRun={() => run(s)}
            disabled={!!loading}
          />
        ))}
      </div>

      <footer className="security-footnote">
        <details>
          <summary>Mapeo entre botones y casos del task spec</summary>
          <ul>
            <li><strong>Caso 1 (Phantom + DPoP válidos)</strong>: cubierto por el botón 1 (login válido).</li>
            <li><strong>Caso 2 (Phantom + DPoP diferente)</strong>: tras login válido, ejecutar el botón 3 con un DPoP keypair fresco genera el rechazo 401.</li>
            <li><strong>Caso 3 (DPoP alterado)</strong>: cubierto por el botón 2.</li>
            <li><strong>Caso 4 (Phantom inválido/expirado)</strong>: cubierto por los botones 4 y 5.</li>
            <li><strong>Caso 5 (Logout con DPoP inválido)</strong>: cubierto por el botón 3.</li>
            <li><strong>Caso 6 (Introspect con token inválido)</strong>: cubierto por el botón 4.</li>
          </ul>
        </details>
      </footer>

      {!result && !loading && (
        <p className="muted small">
          Selecciona un escenario de la lista y click en <em>Ejecutar</em>. La respuesta
          aparecerá en el panel de la derecha.
        </p>
      )}
    </div>
  );
}

// =============================================================================
// Scenario cards
// =============================================================================
type CardProps = {
  scenario: Scenario;
  loading: boolean;
  passed?: boolean;
  isExpanded: boolean;
  onToggleExpand: () => void;
  onRun: () => void;
  disabled: boolean;
};

function ScenarioCard({ scenario, loading, passed, isExpanded, onToggleExpand, onRun, disabled }: CardProps) {
  const req = scenario.renderRequest();
  const outcomeClass = scenario.outcome === 'accept' ? 'ok' : 'fail';
  const outcomeLabel = scenario.outcome === 'accept' ? 'esperado: 200 OK' : `esperado: ${scenario.expectedHttp}`;

  return (
    <article className={`scenario-card ${loading ? 'loading' : ''}`}>
      <header className="scenario-card-header">
        <div className="scenario-card-titles">
          <div className="scenario-card-titlerow">
            <h4 className="scenario-title">{scenario.title}</h4>
            <span className={`badge ${outcomeClass}`}>{outcomeLabel}</span>
            {!loading && passed !== undefined && (
              <span className={`badge ${passed ? 'ok' : 'fail'}`}>
                {passed ? 'coincide' : 'no coincide'}
              </span>
            )}
          </div>
          <p className="scenario-description">{scenario.summary}</p>
          <p className="scenario-cases muted small">Casos task: {scenario.casesCovered.join(', ')}</p>
        </div>
        <div className="scenario-card-actions">
          <button
            type="button"
            className="btn-secondary btn-sm"
            onClick={onToggleExpand}
            aria-expanded={isExpanded}
          >
            {isExpanded ? '▾ Ocultar detalles' : '▸ Ver request completo'}
          </button>
          <button
            type="button"
            className="btn-primary btn-sm"
            onClick={onRun}
            disabled={disabled || loading}
          >
            {loading ? 'Ejecutando…' : 'Ejecutar escenario'}
          </button>
        </div>
      </header>

      {isExpanded && (
        <div className="scenario-card-body">
          <div className="preview-section">
            <h5 className="preview-section-title">Request</h5>
            <KeyValueTable
              rows={[
                { label: 'Method', value: <code>{req.method}</code> },
                { label: 'URL', value: <code>{req.url}</code>, mono: true },
              ]}
            />
          </div>

          <div className="preview-section">
            <h5 className="preview-section-title">Headers</h5>
            <KeyValueTable
              rows={req.headers.map((h) => ({
                label: h.name,
                value: <code className="header-value">{h.value}</code>,
                mono: true,
              }))}
            />
          </div>

          {req.dpopProof && (
            <div className="preview-section">
              <h5 className="preview-section-title">DPoP proof</h5>
              <div className="preview-grid">
                <div>
                  <p className="preview-label">Header</p>
                  <JsonView data={req.dpopProof.header} initialDepth={4} />
                </div>
                <div>
                  <p className="preview-label">Payload</p>
                  <JsonView data={req.dpopProof.payload} initialDepth={3} />
                </div>
                <div className="preview-full">
                  <p className="preview-label">Wire format (compact JWT)</p>
                  <pre className="code-block compact">{req.dpopProof.wireFormat}</pre>
                </div>
              </div>
            </div>
          )}

          {req.jweBody && (
            <div className="preview-section">
              <h5 className="preview-section-title">Request body (JWE envelope)</h5>
              <div className="preview-grid">
                <div>
                  <p className="preview-label">Plaintext (decrypted by aegis-core)</p>
                  <JsonView data={req.jweBody.plaintextShape} initialDepth={4} />
                </div>
                <div className="preview-full">
                  <p className="preview-label">Encrypted (sent on the wire)</p>
                  <pre className="code-block compact">{req.jweBody.encrypted}</pre>
                </div>
              </div>
            </div>
          )}

          {req.rawBody && (
            <div className="preview-section">
              <h5 className="preview-section-title">Request body</h5>
              <JsonView data={req.rawBody} initialDepth={4} />
              {req.rawBodyBytes && (
                <pre className="code-block compact">{req.rawBodyBytes}</pre>
              )}
            </div>
          )}

          <div className="preview-section">
            <h5 className="preview-section-title">What aegis-core validates</h5>
            <ul className="validation-list">
              {req.aegisValidates.map((v, i) => (
                <li key={i}>{v}</li>
              ))}
            </ul>
          </div>

          <div className="preview-section">
            <h5 className="preview-section-title">Expected response</h5>
            <KeyValueTable
              rows={[
                { label: 'HTTP', value: <code>{scenario.expectedHttp}</code> },
                { label: 'Body', value: <code>{scenario.expectedBodyShape}</code> },
              ]}
            />
          </div>
        </div>
      )}
    </article>
  );
}

// =============================================================================
// Scenario builders
// =============================================================================
type BuildArgs = {
  session: ReturnType<typeof getSession>;
  password: string | null | undefined;
  dpopKeyPair: ReturnType<typeof getDpopKeyPair>;
  dpopPublicJwk: Record<string, unknown> | null;
  now: number;
};

function buildScenarios(args: BuildArgs): Scenario[] {
  const { session, password, dpopKeyPair, dpopPublicJwk, now } = args;
  const country = session?.country ?? 'co';
  const channelId = session?.channelId ?? '<channelId>';
  const username = session?.username ?? '<username>';
  const alg = session?.dpopAlg ?? 'ES256';
  const jkt = dpopKeyPair?.jkt ?? '<compute-on-first-login>';
  const expiresIn = session?.expiresAt ? Math.max(0, Math.floor((session.expiresAt - now) / 1000)) : null;

  const dpopBase = {
    header: {
      typ: 'dpop+jwt',
      alg,
      jwk: dpopPublicJwk ?? {
        kty: 'EC',
        crv: 'P-256',
        x: '<generated-on-first-login>',
        y: '<generated-on-first-login>',
      },
    },
  } as const;

  const loginJwePlaintext = {
    user_identifier: username,
    credentials: {
      clientId: channelId,
      pass: password ? '*'.repeat(password.length) : '<password>',
      user_check: username,
    },
    anti_replay: { iat: '<unix-seconds>', jti: '<UUID v4>' },
  };
  const loginUrl = htuForAegis(`/api/v1/${country}/public/login`);
  const tamperedHtu = htuForAegis(`/api/v1/${country}/public/logout`);
  const logoutUrl = htuForAegis(`/api/v1/${country}/public/logout`);
  const expiredReady = expiresIn !== null && expiresIn <= 0;

  return [
    {
      key: 'loginValid',
      title: '1. Login válido',
      summary: 'Login con credenciales reales + DPoP firmado con la clave del browser. aegis-core responde con Phantom tokens.',
      outcome: 'accept',
      expectedHttp: '200 OK',
      expectedBodyShape: '{ access_token, refresh_token, expires_in, token_type: "DPoP" }',
      casesCovered: ['Caso 1 (parcial)'],
      renderRequest: () => ({
        method: 'POST',
        url: loginUrl,
        headers: [
          { name: 'Content-Type', value: 'application/json' },
          {
            name: 'DPoP',
            value: 'DPoP <compact-jwt>  (header.typ=dpop+jwt, alg=' + alg + ', jkt=' + jkt + ')',
          },
        ],
        dpopProof: {
          header: { ...dpopBase.header },
          payload: {
            htm: 'POST',
            htu: loginUrl,
            iat: '<unix-seconds>',
            jti: '<UUID v4>',
            jkt,
          },
          wireFormat: '<header-base64url>.<payload-base64url>.<signature-base64url>',
        },
        jweBody: {
          encrypted:
            'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.<cek>.<iv>.<tag>  (RSA-OAEP-256 / A256GCM, computed on click)',
          plaintextShape: loginJwePlaintext,
        },
        aegisValidates: [
          'RateLimiterGuard: 10 req / 60 s (10 en este prefix)',
          'JWE header: alg ∈ {RSA-OAEP-256, ECDH-ES+A256KW}, enc = A256GCM',
          'JWE decrypt: secure_payload → JSON',
          'JWE envelope: user_identifier === credentials.user_check',
          'JWE: credentials.clientId is UUID v4',
          'AntiReplayGuard: anti_replay.iat dentro de ±5min/30s, anti_replay.jti UUID v4 no usado',
          'DpopLoginGuard: header.typ=dpop+jwt, alg ∈ {ES256, RS256, PS256}, jwk presente',
          'DpopLoginGuard: payload.htm === "POST", payload.htu === URL completa, payload.iat dentro de 5 min, jti UUID v4',
          'UserCheckGuard: user_identifier === credentials.user_check',
          'Keycloak: password grant con clientId resuelto server-side',
          'PhantomSessionService: persiste sesión AES-256-GCM en Redis',
        ],
      }),
      runner: async () => {
        if (!session?.channelId || !session.username || !password) {
          return { ok: false, error: 'Inicia sesión en tab 2 primero.', log: [] };
        }
        return actionLogin({
          country: session.country,
          clientId: session.channelId,
          username: session.username,
          password,
          alg: session.dpopAlg,
        });
      },
    },

    {
      key: 'dpopTamperLogin',
      title: '2. Login con DPoP alterado',
      summary: 'Login con credenciales válidas pero el DPoP proof tiene htu apuntando a otra URL. aegis-core rechaza ANTES de Keycloak.',
      outcome: 'reject',
      expectedHttp: '401 Unauthorized',
      expectedBodyShape: '{ message: "DPOP_HTU_MISMATCH", statusCode: 401 }',
      casesCovered: ['Caso 3'],
      renderRequest: () => ({
        method: 'POST',
        url: loginUrl,
        headers: [
          { name: 'Content-Type', value: 'application/json' },
          { name: 'DPoP', value: 'DPoP <jwt>  (payload.htu FALSIFICADO)' },
        ],
        dpopProof: {
          header: { ...dpopBase.header },
          payload: {
            htm: 'POST',
            htu: tamperedHtu,
            iat: '<unix-seconds>',
            jti: '<UUID v4>',
            jkt,
          },
          wireFormat: '<header-base64url>.<payload-base64url>.<signature-base64url>  (payload.htu ≠ URL real)',
        },
        jweBody: {
          encrypted: 'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.<cek>.<iv>.<tag>',
          plaintextShape: loginJwePlaintext,
        },
        aegisValidates: [
          'Mismas validaciones que el botón 1',
          'DpopLoginGuard: payload.htu === buildDpopTargetUri(request)  ← FALLA AQUÍ',
          'Resultado: throw UnauthorizedException("DPOP_HTU_MISMATCH")',
          'Keycloak nunca es invocado',
        ],
      }),
      runner: async () => {
        if (!session?.channelId || !session.username || !password) {
          return { ok: false, error: 'Inicia sesión en tab 2 primero.', log: [] };
        }
        return actionLogin({
          country: session.country,
          clientId: session.channelId,
          username: session.username,
          password,
          alg: session.dpopAlg,
          proofOptions: {
            tamper: ({ payload }) => {
              payload.htu = htuForAegis(`/api/v1/${session.country}/public/logout`);
            },
          },
        });
      },
    },

    {
      key: 'logoutDifferentDpop',
      title: '3. Logout con DPoP inválido',
      summary:
        'Logout usando un par de claves DPoP nuevo. aegis-core intenta revocar (responde 204) pero internamente la validación jkt falla, así que la sesión phantom NO debe quedar revocada. El test verifica el post-condición: la sesión sigue activa.',
      outcome: 'accept',
      expectedHttp: '204 No Content (logout HTTP) + sesión SIGUE ACTIVA',
      expectedBodyShape:
        '{ introspect: { active: true, ... }, me: { userId, ... } } — la sesión NO fue revocada',
      casesCovered: ['Caso 5'],
      requiresSession: true,
      renderRequest: () => ({
        method: 'POST',
        url: logoutUrl,
        headers: [
          { name: 'Authorization', value: 'Bearer ' + (session?.accessToken ?? '<phantom access token>') },
          { name: 'Content-Type', value: 'application/json' },
          { name: 'DPoP', value: '<raw jwt firmado con clave FRESCA, jkt ≠ session.dpop_jkt, con ath>' },
        ],
        dpopProof: {
          header: {
            typ: 'dpop+jwt',
            alg: session?.dpopAlg ?? 'ES256',
            jwk: { kty: 'EC', crv: 'P-256', x: '<NEW key>', y: '<NEW key>' },
          },
          payload: {
            htm: 'POST',
            htu: logoutUrl,
            iat: '<unix-seconds>',
            jti: '<UUID v4>',
            ath: 'base64url(sha256(phantom_access_token))',
            jkt: '<NEW jkt — distinto al de la sesión>',
          },
          wireFormat: '<header-base64url>.<payload-base64url>.<signature-base64url>',
        },
        rawBody: { refresh_token: session?.refreshToken ?? '<phantom refresh token>' },
        rawBodyBytes: JSON.stringify(
          { refresh_token: session?.refreshToken ?? '<phantom refresh token>' },
          null,
          2,
        ),
        aegisValidates: [
          'RateLimiterGuard (10/60s, identifierType: USER_ID)',
          'DpopAuthGuard (manual call dentro del handler):',
          '  · header.typ=dpop+jwt, alg ∈ {ES256, RS256, PS256}, jwk presente',
          '  · payload.htm === "POST", payload.htu === URL completa',
          '  · payload.iat dentro de 5 min, jti UUID v4 (anti-replay Redis 5 min)',
          '  · payload.ath === base64url(sha256(phantom_access_token))',
          '  · jkt del header === accessSession.dpop_jkt  ← FALLA AQUÍ (jkt distinto)',
          'Authorization: Bearer <phantom_access>  (extractBearerTokenFromRequest exige scheme Bearer)',
          'Body: { refresh_token: "..." } — string UUID v4',
          'Resultado interno: throw UnauthorizedException("Phantom session mismatch")',
          'Respuesta HTTP: 204 (el controller atrapa el error y devuelve noContent)',
          'Post-condición: la sesión phantom NO se elimina (verificado con introspect + /users/me)',
        ],
      }),
      runner: runLogoutWithWrongDpop,
    },

    {
      key: 'introspectInvalidToken',
      title: '4. Introspect con token inválido',
      summary: 'POST al endpoint Internal API con un UUID v4 que no existe en Redis. aegis-core responde 200 con { active: false } (RFC 7662).',
      outcome: 'reject',
      expectedHttp: '200 OK',
      expectedBodyShape: '{ active: false }',
      casesCovered: ['Caso 6'],
      renderRequest: () => ({
        method: 'POST',
        url: '/internal/token/introspect  (proxy → /api/v1/internal/token/introspect)',
        headers: [
          { name: 'X-Internal-API-Key', value: '<server-side, inyectado por el Vite proxy>' },
          { name: 'X-Caller-Service', value: 'aegis-demo-ui' },
          { name: 'Content-Type', value: 'application/json' },
        ],
        rawBody: { token: INVALID_PHANTOM_UUID },
        rawBodyBytes: JSON.stringify({ token: INVALID_PHANTOM_UUID }, null, 2),
        aegisValidates: [
          'InternalApiAuthGuard: X-Internal-API-Key === envs.internalApiKey (inyectado server-side)',
          'Body: { token } — token debe ser UUID v4',
          'ResolveAccessSessionPort: lookup Redis key session:access:<sha256(token)>',
          'Si la sesión no existe o está expirada → return { active: false } (HTTP 200)',
        ],
      }),
      runner: async () => actionIntrospect({ token: INVALID_PHANTOM_UUID }),
    },

    {
      key: 'introspectExpiredToken',
      title: '5. Introspect con token expirado',
      summary: expiredReady
        ? 'El phantom access_token ya pasó su expires_in. aegis-core responde { active: false } porque la entrada Redis ya expiró por TTL.'
        : 'El token aún no ha expirado. Para ejecutar este escenario, espera a que el expires_in de tu sesión llegue a 0 (típicamente 300s).',
      outcome: 'reject',
      expectedHttp: '200 OK',
      expectedBodyShape: '{ active: false } (la entrada Redis ya expiró por TTL)',
      casesCovered: ['Caso 4 (variante expiración)'],
      requiresSession: true,
      renderRequest: () => ({
        method: 'POST',
        url: '/internal/token/introspect  (proxy → /api/v1/internal/token/introspect)',
        headers: [
          { name: 'X-Internal-API-Key', value: '<server-side, inyectado por el Vite proxy>' },
          { name: 'X-Caller-Service', value: 'aegis-demo-ui' },
          { name: 'Content-Type', value: 'application/json' },
        ],
        rawBody: { token: session?.accessToken ?? '<phantom access token from login>' },
        rawBodyBytes: JSON.stringify({ token: session?.accessToken ?? '<access>' }, null, 2),
        aegisValidates: [
          'InternalApiAuthGuard: X-Internal-API-Key OK',
          'ResolveAccessSessionPort: lookup session:access:<sha256(token)>',
          'IntrospectableSession.isActiveAt(now): si exp < now → return { active: false }',
          'Si exp ≥ now: return { active: true, ... } con iat/exp del payload',
        ],
      }),
      runner: async () => {
        if (!session?.accessToken) {
          return { ok: false, error: 'Inicia sesión en tab 2 primero.', log: [] };
        }
        if (!session.expiresAt || session.expiresAt > Date.now()) {
          return {
            ok: false,
            error: 'La sesión aún no expiró. Espera a que el expires_in llegue a 0.',
            log: [],
          };
        }
        return actionIntrospect({ token: session.accessToken });
      },
    },
  ];
}
