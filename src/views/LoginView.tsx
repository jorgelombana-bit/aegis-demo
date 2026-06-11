import { useState } from 'react';

import { actionLogin, type ActionResult } from '../lib/actions';
import { useSessionState } from '../hooks/useSessionState';
import type { DpopAlg } from '../lib/types';

type Props = {
  defaultCountry: string;
  defaultChannelId: string;
  onResult: (result: ActionResult<unknown> | null) => void;
  onLoadingChange?: (loading: boolean) => void;
  result: ActionResult<unknown> | null;
};

export function LoginView({ defaultCountry, defaultChannelId, onResult, onLoadingChange, result }: Props) {
  const session = useSessionState();
  const [country, setCountry] = useState(defaultCountry);
  const [clientId, setClientId] = useState(defaultChannelId);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [alg, setAlg] = useState<DpopAlg>(session?.dpopAlg ?? 'ES256');
  const [loading, setLoading] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    onLoadingChange?.(true);
    onResult(null);
    const res = await actionLogin({ country, clientId, username, password, alg });
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
      <div className="field">
        <label>DPoP algorithm</label>
        <select value={alg} onChange={(e) => setAlg(e.target.value as DpopAlg)}>
          <option value="ES256">ES256 (ECDSA P-256) — recommended</option>
          <option value="RS256">RS256 (RSA PKCS#1 v1.5)</option>
          <option value="PS256">PS256 (RSA-PSS)</option>
        </select>
        <small className="muted">
          Algorithm used to sign the DPoP proof. Rotates the in-memory key pair on submit.
        </small>
      </div>
      <button type="submit" disabled={loading} className="btn-primary">
        {loading ? 'Logging in...' : 'Login (Phantom Token + DPoP)'}
      </button>
      {!result && !loading && (
        <p className="muted">
          Pipeline: <code>JWE (RSA-OAEP-256+A256GCM)</code> + <code>DPoP proof ({alg})</code>{' '}
          + <code>Anti-replay (iat+jti)</code> + <code>Rate limit (10/60s)</code>.
        </p>
      )}
    </form>
  );
}
