import { useState } from 'react';

import { actionGetMe, actionIntrospect, actionLogin, type ActionResult } from '../lib/actions';
import { htuForAegis, generateDpopKeyPair } from '../lib/dpop';
import { getDpopKeyPair, getSession, getStoredPassword } from '../lib/session';
import {
  actionGetMeWithToken,
  INVALID_PHANTOM_UUID,
  isIntrospectInactive,
  runLogoutWithWrongDpop,
} from '../lib/security-runners';
import type { IntrospectTokenResponse } from '../lib/types';

type Props = {
  onResult: (result: ActionResult<unknown> | null) => void;
  onLoadingChange?: (loading: boolean) => void;
  result: ActionResult<unknown> | null;
};

type ScenarioKind = 'accept' | 'reject' | 'introspect-inactive' | 'logout-rejected';

type Scenario = {
  key: string;
  label: string;
  description: string;
  kind: ScenarioKind;
};

const CASO_SCENARIOS: Scenario[] = [
  {
    key: 'meValid',
    label: 'Caso 1 — Token y DPoP válidos',
    description: 'GET /users/me con Phantom y DPoP correctos. Esperado: aceptado (HTTP 200).',
    kind: 'accept',
  },
  {
    key: 'meDifferentDpop',
    label: 'Caso 2 — Phantom + DPoP diferente',
    description: 'GET /users/me con otro jkt. Esperado: rechazado (HTTP 401).',
    kind: 'reject',
  },
  {
    key: 'meDpopTamperHtu',
    label: 'Caso 3 — DPoP alterado',
    description: 'GET /users/me con DPoP modificado (htu inválido). Esperado: rechazado (HTTP 401).',
    kind: 'reject',
  },
  {
    key: 'meInvalidPhantom',
    label: 'Caso 4 — Phantom Token inválido',
    description: 'GET /users/me con token sin sesión. Esperado: rechazado (HTTP 401).',
    kind: 'reject',
  },
  {
    key: 'logoutDifferentDpop',
    label: 'Caso 5 — Logout con DPoP inválido',
    description: 'Logout con jkt distinto. aegis responde 204; verificación: introspect active:true.',
    kind: 'logout-rejected',
  },
  {
    key: 'introspectInvalidToken',
    label: 'Caso 6 — Introspect token inválido',
    description: 'Introspect con UUID inexistente. Esperado: active:false.',
    kind: 'introspect-inactive',
  },
];

const MODO_TEST_SCENARIOS: Scenario[] = [
  {
    key: 'loginValid',
    label: 'Login válido',
    description: 'Login con credenciales y DPoP correctos. Esperado: Phantom tokens.',
    kind: 'accept',
  },
  {
    key: 'dpopTamperLogin',
    label: 'Login con DPoP alterado',
    description: 'Login con htu falsificado. Esperado: rechazado (HTTP 401).',
    kind: 'reject',
  },
  {
    key: 'logoutDifferentDpop',
    label: 'Logout con DPoP alterado',
    description: 'Logout con jkt distinto. aegis responde 204; verificación: introspect active:true.',
    kind: 'logout-rejected',
  },
  {
    key: 'introspectInvalidToken',
    label: 'Introspect con token inválido',
    description: 'Token inexistente. Esperado: active:false.',
    kind: 'introspect-inactive',
  },
  {
    key: 'introspectExpiredToken',
    label: 'Introspect con token expirado',
    description: 'Introspect tras expires_in. Esperado: active:false.',
    kind: 'introspect-inactive',
  },
];

function scenarioPassed(result: ActionResult<unknown>, kind: ScenarioKind): boolean {
  if (kind === 'introspect-inactive') {
    return isIntrospectInactive(result as ActionResult<IntrospectTokenResponse>);
  }
  if (kind === 'logout-rejected') return result.ok;
  if (kind === 'accept') return result.ok;
  return !result.ok;
}

export function SecurityTestView({ onResult, onLoadingChange, result }: Props) {
  const [loading, setLoading] = useState<string | null>(null);
  const [lastResults, setLastResults] = useState<Record<string, boolean>>({});

  const run = async (scenario: Scenario, resultKey: string) => {
    const runner = RUNNERS[scenario.key];
    if (!runner) return;
    setLoading(resultKey);
    onLoadingChange?.(true);
    onResult(null);
    const res = await runner();
    const passed = scenarioPassed(res, scenario.kind);
    setLastResults((prev) => ({ ...prev, [resultKey]: passed }));
    onResult(res);
    setLoading(null);
    onLoadingChange?.(false);
  };

  return (
    <div className="security-test">
      <section className="security-section">
        <h3>Validación de Seguridad DPoP</h3>
        <div className="security-grid">
          {CASO_SCENARIOS.map((s) => (
            <ScenarioButton
              key={s.key}
              scenario={s}
              loading={loading === s.key}
              passed={lastResults[s.key]}
              onClick={() => run(s, s.key)}
              disabled={!!loading}
            />
          ))}
        </div>
      </section>

      <section className="security-section">
        <h3>Modo Test de Seguridad</h3>
        <div className="security-grid">
          {MODO_TEST_SCENARIOS.map((s) => (
            <ScenarioButton
              key={`modo-${s.key}`}
              scenario={s}
              loading={loading === `modo-${s.key}`}
              passed={lastResults[`modo-${s.key}`]}
              onClick={() => run(s, `modo-${s.key}`)}
              disabled={!!loading}
            />
          ))}
        </div>
      </section>

      {!result && !loading && (
        <p className="muted small">
          Pre-requisito: tab 1 (Create User) y tab 2 (Login). Token expirado: esperar al{' '}
          <code>expires_in</code> del login.
        </p>
      )}
    </div>
  );
}

type BtnProps = {
  scenario: Scenario;
  loading: boolean;
  passed?: boolean;
  disabled: boolean;
  onClick: () => void;
};

function ScenarioButton({ scenario, loading, passed, disabled, onClick }: BtnProps) {
  return (
    <button type="button" className={`scenario ${loading ? 'loading' : ''}`} onClick={onClick} disabled={disabled}>
      <span className="scenario-label">{scenario.label}</span>
      <span className="scenario-description">{scenario.description}</span>
      {loading && <span className="badge loading">running</span>}
      {!loading && passed !== undefined && (
        <span className={`badge ${passed ? 'ok' : 'fail'}`}>{passed ? 'expected' : 'unexpected'}</span>
      )}
    </button>
  );
}

const RUNNERS: Record<string, () => Promise<ActionResult<unknown>>> = {
  meValid: async () => {
    const session = getSession();
    if (!session?.accessToken) {
      return { ok: false, error: 'Inicia sesión en tab 2 primero.', log: [] };
    }
    return actionGetMe();
  },

  meDifferentDpop: async () => {
    const session = getSession();
    if (!session?.accessToken) {
      return { ok: false, error: 'Inicia sesión en tab 2 primero.', log: [] };
    }
    const altPair = await generateDpopKeyPair(session.dpopAlg);
    return actionGetMe({ proofOptions: { overrideKeyPair: altPair } });
  },

  meDpopTamperHtu: async () => {
    const session = getSession();
    if (!session?.accessToken) {
      return { ok: false, error: 'Inicia sesión en tab 2 primero.', log: [] };
    }
    return actionGetMe({
      proofOptions: {
        tamper: ({ payload }) => {
          payload.htu = htuForAegis('/api/v1/auth/encryption-key');
        },
      },
    });
  },

  meInvalidPhantom: async () => {
    const kp = getDpopKeyPair();
    if (!kp) {
      return { ok: false, error: 'Inicia sesión en tab 2 primero.', log: [] };
    }
    return actionGetMeWithToken(INVALID_PHANTOM_UUID, kp);
  },

  logoutDifferentDpop: runLogoutWithWrongDpop,

  introspectInvalidToken: async () => actionIntrospect({ token: INVALID_PHANTOM_UUID }),

  loginValid: async () => {
    const session = getSession();
    const password = getStoredPassword();
    if (!session?.channelId || !session.username || !password) {
      return { ok: false, error: 'Haz Login en tab 2 primero.', log: [] };
    }
    return actionLogin({
      country: session.country,
      clientId: session.channelId,
      username: session.username,
      password,
      alg: session.dpopAlg,
    });
  },

  dpopTamperLogin: async () => {
    const session = getSession();
    const password = getStoredPassword();
    if (!session?.channelId || !session.username || !password) {
      return { ok: false, error: 'Haz Login en tab 2 primero.', log: [] };
    }
    return actionLogin({
      country: session.country,
      clientId: session.channelId,
      username: session.username,
      password,
      alg: session.dpopAlg,
      proofOptions: {
        tamper: ({ payload }) => {
          payload.htu = htuForAegis(`/api/v1/${session.country}/public/logout`);
        },
      },
    });
  },

  introspectExpiredToken: async () => {
    const session = getSession();
    if (!session?.accessToken || !session.expiresAt) {
      return { ok: false, error: 'Inicia sesión en tab 2 primero.', log: [] };
    }
    const remainingMs = session.expiresAt - Date.now();
    if (remainingMs > 0) {
      return {
        ok: false,
        error: `El token aún no expiró (faltan ~${Math.ceil(remainingMs / 1000)}s).`,
        log: [],
      };
    }
    return actionIntrospect({ token: session.accessToken });
  },
};
