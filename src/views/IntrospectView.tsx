import { useState } from 'react';

import { actionIntrospect, type ActionResult } from '../lib/actions';
import { useSessionState } from '../hooks/useSessionState';

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

  return (
    <form onSubmit={submit} className="form">
      <div className="field">
        <label>Phantom access token (UUID v4)</label>
        <input value={token} onChange={(e) => setToken(e.target.value)} required className="mono" />
        <small className={`muted ${isValid ? '' : 'warn'}`}>
          {isValid ? 'Format OK (UUID v4).' : 'Must be a UUID v4 (e.g. 550e8400-...-446655440000).'}
        </small>
      </div>
      <button type="submit" disabled={loading || !isValid} className="btn-primary">
        {loading ? 'Introspecting...' : 'Introspect (Internal API Guard)'}
      </button>
      {!result && !loading && (
        <p className="muted">
          Pipeline: <code>X-Internal-API-Key</code> (injected by Vite proxy) +{' '}
          <code>InternalApiAuthGuard</code>. Body: <code>{'{ token: <UUID> }'}</code>.
        </p>
      )}
    </form>
  );
}
