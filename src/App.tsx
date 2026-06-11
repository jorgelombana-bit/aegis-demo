import { useState } from 'react';

import { ResponsePanel } from './components/ResponsePanel';
import { TabBar, type TabKey } from './components/TabBar';
import type { ActionResult } from './lib/actions';
import { useSessionState } from './hooks/useSessionState';
import { CreateUserView } from './views/CreateUserView';
import { IntrospectView } from './views/IntrospectView';
import { LoginView } from './views/LoginView';
import { LogoutView } from './views/LogoutView';
import { MeView } from './views/MeView';
import { RefreshView } from './views/RefreshView';
import { SecurityTestView } from './views/SecurityTestView';
import './App.css';

const DEFAULT_COUNTRY = (import.meta.env.VITE_DEFAULT_COUNTRY as string | undefined) ?? 'co';
const DEFAULT_CHANNEL_ID =
  (import.meta.env.VITE_DEFAULT_CHANNEL_ID as string | undefined) ?? 'a1b2c3d4-e5f6-4789-a012-000000000001';
const aegisTarget =
  (import.meta.env.VITE_AEGIS_PROXY_TARGET as string | undefined) || 'https://aegis-dev.preprodcxr.co';

function App() {
  const [tab, setTab] = useState<TabKey>('createUser');
  const [result, setResult] = useState<ActionResult<unknown> | null>(null);
  const [loading, setLoading] = useState(false);
  const session = useSessionState();

  const handleResult = (next: ActionResult<unknown> | null) => {
    setResult(next);
    if (next !== null) setLoading(false);
  };

  const handleLoadingChange = (isLoading: boolean) => {
    setLoading(isLoading);
  };

  const renderView = () => {
    const common = { onResult: handleResult, onLoadingChange: handleLoadingChange, result };
    switch (tab) {
      case 'createUser':
        return <CreateUserView defaultCountry={DEFAULT_COUNTRY} defaultChannelId={DEFAULT_CHANNEL_ID} {...common} />;
      case 'login':
        return <LoginView defaultCountry={DEFAULT_COUNTRY} defaultChannelId={DEFAULT_CHANNEL_ID} {...common} />;
      case 'logout':
        return <LogoutView {...common} />;
      case 'introspect':
        return <IntrospectView {...common} />;
      case 'me':
        return <MeView {...common} />;
      case 'refresh':
        return <RefreshView {...common} />;
      case 'security':
        return <SecurityTestView {...common} />;
    }
  };

  return (
    <div className="layout">
      <header className="app-header">
        <h1>Aegis Demo UI</h1>
        <p className="subtitle">
          Phantom Token · DPoP · Rate Limiting · Internal API Guard
        </p>
        <p className="env-info muted">
          The browser talks to <code>http://localhost:5173</code>; the Vite dev server forwards
          to <code>{aegisTarget}</code>. Each proxy hop is also logged in the dev terminal.
        </p>
        {session && (
          <div className="session-banner">
            <span>
              Sesión activa · alg=<code>{session.dpopAlg}</code> · jkt=<code>{session.dpopJkt}</code>
            </span>
            {session.username && <span> · user=<strong>{session.username}</strong></span>}
          </div>
        )}
      </header>

      <TabBar active={tab} onChange={(k) => { setTab(k); setResult(null); setLoading(false); }} />

      <main className="app-main">
        <section className="view-pane">{renderView()}</section>
        <section className="response-pane">
          <ResponsePanel
            title="Aegis response"
            result={result}
            loading={loading}
          />
        </section>
      </main>

      <footer className="app-footer">
        <details>
          <summary>About this demo</summary>
          <p>
            Single-page UI built with React 19 + Vite. It uses the browser's WebCrypto API
            and <code>jose</code> to:
          </p>
          <ul>
            <li>Fetch the JWE public key from <code>GET /api/v1/auth/encryption-key</code>.</li>
            <li>Generate an EC / RSA DPoP key pair on demand (ES256/RS256/PS256).</li>
            <li>Build a DPoP proof JWT with header <code>typ=dpop+jwt</code> and claims <code>htm</code>, <code>htu</code>, <code>iat</code>, <code>jti</code> (and <code>ath</code> when required).</li>
            <li>Encrypt request payloads with JWE (RSA-OAEP-256 / A256GCM) as expected by aegis-core.</li>
            <li>Call aegis-core through the Vite dev server proxy: <code>/api/*</code> for public + phantom-protected endpoints, <code>/internal/*</code> for the Internal API.</li>
          <li>Full Phantom-token lifecycle: <code>login</code> → <code>/users/me</code> → <code>refresh-token</code> → <code>logout</code>.</li>
          </ul>
        </details>
      </footer>
    </div>
  );
}

export default App;
