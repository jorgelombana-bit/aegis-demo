import { useState } from 'react';

import { actionCreateUser, type ActionResult } from '../lib/actions';

type Props = {
  defaultCountry: string;
  defaultChannelId: string;
  onResult: (result: ActionResult<unknown> | null) => void;
  onLoadingChange?: (loading: boolean) => void;
  result: ActionResult<unknown> | null;
};

export function CreateUserView({ defaultCountry, defaultChannelId, onResult, onLoadingChange, result }: Props) {
  const [country, setCountry] = useState(defaultCountry);
  const [clientId, setClientId] = useState(defaultChannelId);
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    onLoadingChange?.(true);
    onResult(null);
    const res = await actionCreateUser({ country, clientId, username, email, password });
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
      </div>
      <button type="submit" disabled={loading} className="btn-primary">
        {loading ? 'Registering...' : 'Create User'}
      </button>
      {loading && <p className="muted">Encrypting payload with JWE and posting to aegis-core...</p>}
      {!result && !loading && (
        <p className="muted">
          Calls <code>POST /api/v1/{country || 'co'}/public/user</code> with a JWE envelope
          (alg=<code>RSA-OAEP-256</code>, enc=<code>A256GCM</code>).
        </p>
      )}
    </form>
  );
}
