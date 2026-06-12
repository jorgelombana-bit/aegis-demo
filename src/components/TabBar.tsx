export type TabKey = 'createUser' | 'login' | 'logout' | 'introspect' | 'security';

type Tab = { key: TabKey; label: string; description: string };

const TABS: Tab[] = [
  { key: 'createUser', label: '1. Create User', description: 'Registro público (JWE)' },
  { key: 'login', label: '2. Login', description: 'Phantom Token + DPoP' },
  { key: 'logout', label: '3. Logout', description: 'Phantom Token + DPoP' },
  { key: 'introspect', label: '4. Introspect', description: 'Internal API Guard' },
  { key: 'security', label: '5. Security Test', description: 'Casos DPoP + Modo Test' },
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
