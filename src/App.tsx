import { useState } from 'react';

import { ResponsePanel } from './components/ResponsePanel';
import { TabBar, type TabKey } from './components/TabBar';
import type { ActionResult } from './lib/actions';
import { useSessionState } from './hooks/useSessionState';
import { CreateUserView } from './views/CreateUserView';
import { IntrospectView } from './views/IntrospectView';
import { LoginView } from './views/LoginView';
import { LogoutView } from './views/LogoutView';
import { SecurityTestView } from './views/SecurityTestView';
import './App.css';

const DEFAULT_COUNTRY = (import.meta.env.VITE_DEFAULT_COUNTRY as string | undefined) ?? 'co';
const DEFAULT_CHANNEL_ID =
  (import.meta.env.VITE_DEFAULT_CHANNEL_ID as string | undefined) ?? 'f51bc49c-50f6-477d-873e-2408fff7746e';

function App() {
  const [tab, setTab] = useState<TabKey>('createUser');
  const [result, setResult] = useState<ActionResult<unknown> | null>(null);
  const [loading, setLoading] = useState(false);
  const session = useSessionState();

  const handleResult = (next: ActionResult<unknown> | null) => {
    setResult(next);
    if (next !== null) setLoading(false);
  };

  const renderView = () => {
    const common = { onResult: handleResult, onLoadingChange: setLoading, result };
    switch (tab) {
      case 'createUser':
        return <CreateUserView defaultCountry={DEFAULT_COUNTRY} defaultChannelId={DEFAULT_CHANNEL_ID} {...common} />;
      case 'login':
        return <LoginView defaultCountry={DEFAULT_COUNTRY} defaultChannelId={DEFAULT_CHANNEL_ID} {...common} />;
      case 'logout':
        return <LogoutView {...common} />;
      case 'introspect':
        return <IntrospectView {...common} />;
      case 'security':
        return <SecurityTestView {...common} />;
    }
  };

  return (
    <div className="layout">
      <header className="app-header">
        <h1>Aegis Demo UI</h1>
        <p className="subtitle">Phantom Token · DPoP · Rate Limiting · Internal API Guard</p>
        {session && (
          <div className="session-banner">
            <span>
              Sesión · alg=<code>{session.dpopAlg}</code> · jkt=<code>{session.dpopJkt}</code>
            </span>
            {session.username && <span> · user=<strong>{session.username}</strong></span>}
          </div>
        )}
      </header>

      <TabBar active={tab} onChange={(k) => { setTab(k); setResult(null); setLoading(false); }} />

      <main className="app-main">
        <section className="view-pane">{renderView()}</section>
        <section className="response-pane">
          <ResponsePanel title="Aegis response" result={result} loading={loading} />
        </section>
      </main>
    </div>
  );
}

export default App;
