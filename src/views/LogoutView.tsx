import { useState } from 'react';

import { actionLogout, type ActionResult } from '../lib/actions';
import { useSessionState } from '../hooks/useSessionState';

type Props = {
  onResult: (result: ActionResult<unknown> | null) => void;
  onLoadingChange?: (loading: boolean) => void;
  result: ActionResult<unknown> | null;
};

export function LogoutView({ onResult, onLoadingChange, result }: Props) {
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
            <tr>
              <th>User</th>
              <td>{session.username}</td>
            </tr>
            <tr>
              <th>Channel clientId</th>
              <td className="mono">{session.channelId}</td>
            </tr>
            <tr>
              <th>Phantom access_token</th>
              <td className="mono">{session.accessToken}</td>
            </tr>
            <tr>
              <th>DPoP jkt</th>
              <td className="mono">{session.dpopJkt}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <button type="submit" disabled={loading} className="btn-primary">
        {loading ? 'Logging out...' : 'Logout (revoke phantom + Keycloak refresh)'}
      </button>
      {!result && !loading && (
        <p className="muted">
          Pipeline: <code>JWE envelope</code> + <code>Authorization: DPoP &lt;access&gt;</code> +{' '}
          <code>DPoP proof (ath=sha256(access))</code> + <code>Rate limit</code>.
        </p>
      )}
    </form>
  );
}
