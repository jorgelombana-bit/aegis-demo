import { useState } from 'react';

import { actionGetMe, type ActionResult } from '../lib/actions';
import { useSessionState } from '../hooks/useSessionState';

type Props = {
  onResult: (result: ActionResult<unknown> | null) => void;
  onLoadingChange?: (loading: boolean) => void;
  result: ActionResult<unknown> | null;
};

export function MeView({ onResult, onLoadingChange, result }: Props) {
  const session = useSessionState();
  const [loading, setLoading] = useState(false);

  if (!session || !session.accessToken) {
    return (
      <div className="empty-state">
        <p>No active phantom session.</p>
        <p className="muted">Login first to call the protected /users/me endpoint.</p>
      </div>
    );
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    onLoadingChange?.(true);
    onResult(null);
    const res = await actionGetMe();
    onResult(res);
    setLoading(false);
    onLoadingChange?.(false);
  };

  return (
    <form onSubmit={submit} className="form">
      <p className="muted">
        Calls <code>GET /api/v1/users/me</code>. This endpoint is guarded by{' '}
        <code>PhantomTokenGuard</code> + <code>DpopAuthGuard</code> + <code>RateLimiterGuard</code>{' '}
        in aegis-core, so it is the perfect smoke test for the Phantom ↔ DPoP binding.
      </p>
      <button type="submit" disabled={loading} className="btn-primary">
        {loading ? 'Calling /users/me...' : 'GET /users/me (validate Phantom ↔ DPoP)'}
      </button>
      {!result && !loading && <p className="muted">Click to validate the link between the current Phantom token and the DPoP key pair.</p>}
    </form>
  );
}
