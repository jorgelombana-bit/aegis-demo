import { useState } from 'react';

import { actionLogin, type ActionResult } from '../lib/actions';

type Props = {
  defaultCountry: string;
  defaultChannelId: string;
  onResult: (result: ActionResult<unknown> | null) => void;
  onLoadingChange?: (loading: boolean) => void;
  result: ActionResult<unknown> | null;
};

const DPOP_ALG = 'ES256' as const;

export function LoginView({ defaultCountry, defaultChannelId, onResult, onLoadingChange, result }: Props) {
  const [country, setCountry] = useState(defaultCountry);
  const [clientId, setClientId] = useState(defaultChannelId);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    onLoadingChange?.(true);
    onResult(null);
    const res = await actionLogin({ country, clientId, username, password, alg: DPOP_ALG });
    onResult(res);
    setLoading(false);
    onLoadingChange?.(false);
  };

  return (
    <form onSubmit={submit} className="form">
      <div className="field-row">
        <div className="field">
          <label>Country (ISO-2)</label>
          <input value={country} onChange={(e) => setCountry(e.target.value)} maxLength={2} required />
        </div>
        <div className="field">
          <label>Channel clientId (UUID)</label>
          <input value={clientId} onChange={(e) => setClientId(e.target.value)} required />
          <small className="muted">data.id del canal en aegis-admin; editable.</small>
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
      <button type="submit" disabled={loading} className="btn-primary">
        {loading ? 'Logging in...' : 'Login (Phantom Token + DPoP)'}
      </button>
      {!result && !loading && (
        <p className="muted">
          Pipeline: <code>JWE (RSA-OAEP-256+A256GCM)</code> + <code>DPoP proof (ES256, EC P-256)</code>{' '}
          + <code>Anti-replay (iat+jti)</code> + <code>Rate limit (10/60s)</code>.
        </p>
      )}
    </form>
  );
}
