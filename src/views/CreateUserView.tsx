import { useState } from 'react';

import { RequestPreview } from '../components/RequestPreview';
import { actionCreateUser, type ActionResult } from '../lib/actions';
import { htuForAegis } from '../lib/dpop';

type Props = {
  defaultCountry: string;
  defaultOauthClientId: string;
  onResult: (result: ActionResult<unknown> | null) => void;
  onLoadingChange?: (loading: boolean) => void;
  result: ActionResult<unknown> | null;
};

export function CreateUserView({ defaultCountry, defaultOauthClientId, onResult, onLoadingChange, result }: Props) {
  const [country, setCountry] = useState(defaultCountry);
  const [oauthClientId, setOauthClientId] = useState(defaultOauthClientId);
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    onLoadingChange?.(true);
    onResult(null);
    const res = await actionCreateUser({ country, clientId: oauthClientId, username, email, password });
    onResult(res);
    setLoading(false);
    onLoadingChange?.(false);
  };

  const url = htuForAegis(`/api/v1/${country || 'co'}/public/user`);

  return (
    <form onSubmit={submit} className="form">
      <div className="field-row">
        <div className="field">
          <label>Country (ISO-2)</label>
          <input value={country} onChange={(e) => setCountry(e.target.value)} maxLength={2} required />
          <small className="muted">Se usa para resolver el realm de Keycloak: <code>puntored-{'{country}'}</code>.</small>
        </div>
        <div className="field">
          <label>Channel clientId</label>
          <input
            value={oauthClientId}
            onChange={(e) => setOauthClientId(e.target.value)}
            required
          />
          <small className="muted">
            Keycloak OAuth/OIDC client identifier (p. ej. <code>aegis-AEGIS-DEMO-e8a6cb</code>).
            aegis-core lo reenvía tal cual a aegis-admin (gRPC CreateUser) y se persiste
            como <code>channelId</code> en la auditoría. NO es un UUID.
          </small>
        </div>
      </div>
      <div className="field-row">
        <div className="field">
          <label>Username</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)} required />
        </div>
        <div className="field">
          <label>Email</label>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </div>
      </div>
      <div className="field">
        <label>Password</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          minLength={10}
        />
        <small className="muted">
          Mínimo 10 caracteres. aegis-admin aplica la política de password del canal (suscripción).
        </small>
      </div>

      <RequestPreview
        title="Request completo — click para ver"
        method="POST"
        url={url}
        headers={[
          { name: 'Content-Type', value: 'application/json' },
        ]}
        jweBody={{
          encrypted:
            'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.<cek>.<iv>.<tag>  (RSA-OAEP-256 / A256GCM, computed on click)',
          plaintextShape: {
            clientId: oauthClientId || '<Keycloak OAuth clientId>',
            userData: { username: username || '<username>', email: email || '<email>', password: '***' },
            credentials: { user_check: email || '<email>' },
            anti_replay: { iat: '<unix-seconds, generado al submit>', jti: '<UUID v4, generado al submit>' },
          },
        }}
        why={[
          { q: '¿Por qué JWE?', a: 'Las credenciales (userData.password, clientId) viajan encriptadas con la clave pública RSA-OAEP-256 de aegis-core. Sin TLS adicional, sólo aegis-core puede descifrar el payload.' },
          { q: '¿Por qué user_identifier === credentials.user_check?', a: 'El interceptor JweRegistrationDecryptInterceptor exige esta igualdad para detectar payloads manipulados fuera del envelope (ataque de cross-user).' },
          { q: '¿Por qué anti_replay?', a: 'Cada registro lleva un jti UUID v4 único + iat dentro de 5 min. aegis-core cachea el jti en Redis (TTL 5 min) y rechaza reintentos.' },
          { q: '¿Por qué clientId es el Keycloak clientId y NO el UUID del canal?', a: 'Desde el fix "create user" (78d8da8) el DTO quitó la validación @IsUUID(); ahora el campo es un string no vacío. aegis-core lo reenvía a aegis-admin gRPC CreateUser, que crea el usuario en el realm puntored-{country} asociado a ese client.' },
        ]}
        aegisValidates={[
          'RateLimiterGuard: 10 req / 60 s (prefix RATE_LIMIT_USER_SELF_SERVICE_REGISTRATION)',
          'JweRegistrationDecryptInterceptor: header.alg ∈ {RSA-OAEP-256, ECDH-ES+A256KW}, enc = A256GCM',
          'JweRegistrationDecryptInterceptor: secure_payload → JSON con la forma esperada',
          'user_identifier === credentials.user_check',
          'clientId es un string no vacío (Keycloak OAuth clientId; ya NO se valida como UUID v4)',
          'userData.email is valid email',
          'anti_replay.iat dentro de 300s ± 30s clock skew; anti_replay.jti es UUID v4',
          'AntiReplayGuard (manual): registra jti en Redis con TTL 5 min, rechaza si ya existe',
          'aegis-admin gRPC CreateUser: crea el usuario en Keycloak, valida política de password del canal',
          'Respuestas: 201 (éxito) · 400 (DTO inválido) · 401 (JWE decrypt falló / anti-replay rechazado) · 409 (usuario/email ya existe) · 429 (rate limit) · 502 (aegis-admin no disponible)',
        ]}
        expectedHttp="201 Created"
        expectedBody='{ message: "Registration successful. Sign in with your credentials." }'
      />

      <button type="submit" disabled={loading || !oauthClientId.trim()} className="btn-primary">
        {loading ? 'Registering…' : 'Create User'}
      </button>
      {loading && <p className="muted">Encrypting payload with JWE and posting to aegis-core…</p>}
      {!loading && result && (
        <p className="muted small">
          Última respuesta: HTTP {result.httpStatus ?? '?'} —{' '}
          {result.ok ? 'éxito' : `falló (${result.error ?? 'sin mensaje'})`}.{' '}
          Para detalles completos, mira el panel "Aegis response" a la derecha.
        </p>
      )}
    </form>
  );
}
