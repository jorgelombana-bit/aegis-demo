import { JsonView } from '../components/JsonView';
import { KeyValueTable } from '../components/KeyValueTable';
import { useSessionState } from '../hooks/useSessionState';
import { resetSession } from '../lib/session';

export function SessionView() {
  const session = useSessionState();

  if (!session) {
    return (
      <div className="empty-state">
        <p>No hay sesión activa.</p>
        <p className="muted">Crea un usuario o inicia sesión para inicializar la sesión DPoP.</p>
      </div>
    );
  }

  return (
    <div className="session-view">
      <KeyValueTable
        title="DPoP key pair"
        rows={[
          { label: 'Algorithm', value: <code>{session.dpopAlg}</code> },
          { label: 'JKT thumbprint', value: <code>{session.dpopJkt}</code>, mono: true },
          { label: 'Public JWK', value: <JsonView data={session.dpopPublicJwk} initialDepth={3} /> },
        ]}
      />
      <KeyValueTable
        title="Identity"
        rows={[
          { label: 'Country', value: <code>{session.country}</code> },
          { label: 'Username', value: session.username ?? <em>not set</em> },
          { label: 'Channel clientId', value: session.channelId ? <code>{session.channelId}</code> : <em>not set</em> },
        ]}
      />
      <KeyValueTable
        title="Phantom tokens"
        rows={[
          {
            label: 'access_token',
            value: session.accessToken ? <code>{session.accessToken}</code> : <em>none</em>,
            mono: true,
          },
          {
            label: 'refresh_token',
            value: session.refreshToken ? <code>{session.refreshToken}</code> : <em>none</em>,
            mono: true,
          },
          {
            label: 'expires_at',
            value: session.expiresAt ? new Date(session.expiresAt).toISOString() : <em>unknown</em>,
            mono: true,
          },
        ]}
      />
      <KeyValueTable
        title="Anti-replay"
        rows={[
          { label: 'last jti', value: session.lastJti ? <code>{session.lastJti}</code> : <em>none</em>, mono: true },
          {
            label: 'last iat',
            value: session.jtiIssuedAt ? new Date(session.jtiIssuedAt * 1000).toISOString() : <em>none</em>,
            mono: true,
          },
        ]}
      />
      <div>
        <button className="btn-secondary" onClick={() => resetSession()}>
          Reset session (clear DPoP key + tokens)
        </button>
      </div>
    </div>
  );
}
