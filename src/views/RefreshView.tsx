import { useState } from 'react';

import { actionRefresh, type ActionResult } from '../lib/actions';
import { useSessionState } from '../hooks/useSessionState';

type Props = {
  onResult: (result: ActionResult<unknown> | null) => void;
  onLoadingChange?: (loading: boolean) => void;
  result: ActionResult<unknown> | null;
};

export function RefreshView({ onResult, onLoadingChange, result }: Props) {
  const session = useSessionState();
  const [loading, setLoading] = useState(false);

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
    const res = await actionRefresh();
    onResult(res);
    setLoading(false);
    onLoadingChange?.(false);
  };

  return (
    <form onSubmit={submit} className="form">
      <div className="kv">
        <table>
          <tbody>
            <tr>
              <th>Current access_token</th>
              <td className="mono">{session.accessToken}</td>
            </tr>
            <tr>
              <th>Current refresh_token</th>
              <td className="mono">{session.refreshToken}</td>
            </tr>
            <tr>
              <th>Channel clientId</th>
              <td className="mono">{session.channelId}</td>
            </tr>
            <tr>
              <th>DPoP jkt</th>
              <td className="mono">{session.dpopJkt}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <button type="submit" disabled={loading} className="btn-primary">
        {loading ? 'Refreshing...' : 'Refresh tokens (rotate phantom)'}
      </button>
      {!result && !loading && (
        <p className="muted">
          Pipeline: <code>PhantomTokenGuard</code> + <code>DpopAuthGuard</code> +{' '}
          <code>RateLimiterGuard</code>. Body: <code>application/json</code>{' '}
          with <code>{'{ refresh_token, client_id }'}</code>. DPoP proof must include{' '}
          <code>ath = base64url(sha256(access))</code>. The DPoP keypair is{' '}
          <strong>not</strong> rotated by the server.
        </p>
      )}
    </form>
  );
}
