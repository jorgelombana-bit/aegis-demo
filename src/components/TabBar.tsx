export type TabKey = 'createUser' | 'login' | 'logout' | 'introspect' | 'me' | 'refresh' | 'security';

type Tab = { key: TabKey; label: string; description: string };

const TABS: Tab[] = [
  { key: 'createUser', label: '1. Create User', description: 'Self-service registration (JWE + Rate Limit)' },
  { key: 'login', label: '2. Login', description: 'Phantom Token + DPoP + Rate Limit' },
  { key: 'logout', label: '3. Logout', description: 'Revoke phantom session (Bearer + DPoP)' },
  { key: 'introspect', label: '4. Introspect', description: 'Internal API Guard' },
  { key: 'me', label: '5. /users/me', description: 'Validate Phantom ↔ DPoP link' },
  { key: 'refresh', label: '6. Refresh', description: 'Rotate phantom tokens (JSON body)' },
  { key: 'security', label: '7. Security Test', description: 'Failure scenarios' },
];

type Props = {
  active: TabKey;
  onChange: (key: TabKey) => void;
};

export function TabBar({ active, onChange }: Props) {
  return (
    <nav className="tab-bar" role="tablist">
      {TABS.map((t) => (
        <button
          key={t.key}
          role="tab"
          aria-selected={active === t.key}
          className={`tab ${active === t.key ? 'active' : ''}`}
          onClick={() => onChange(t.key)}
        >
          <span className="tab-label">{t.label}</span>
          <span className="tab-description">{t.description}</span>
        </button>
      ))}
    </nav>
  );
}
