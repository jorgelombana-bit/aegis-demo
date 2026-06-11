import { useState } from 'react';

import { actionGetMe, actionIntrospect, actionLogin, actionLogout, type ActionResult } from '../lib/actions';
import { generateDpopKeyPair, type DpopKeyPair } from '../lib/dpop';
import { getDpopKeyPair, getSession } from '../lib/session';
import { actionGetMeWithToken } from '../lib/security-runners';

type Props = {
  onResult: (result: ActionResult<unknown> | null) => void;
  onLoadingChange?: (loading: boolean) => void;
  result: ActionResult<unknown> | null;
};

const SCENARIOS: Array<{ key: string; label: string; description: string }> = [
  {
    key: 'loginValid',
    label: 'Login válido (Phantom + DPoP correctos)',
    description: 'Login con credenciales reales + DPoP firmado correctamente. Devuelve Phantom tokens. Si no hay usuario creado aún, este botón falla con 401/404 — usar primero "1. Create User".',
  },
  {
    key: 'dpopTamperHtu',
    label: 'Login con DPoP alterado (htu)',
    description: 'Firma DPoP con un htu que no coincide con la URL del request. aegis responde 401 DPOP_HTU_MISMATCH.',
  },
  {
    key: 'logoutDifferentDpop',
    label: 'Logout con DPoP diferente (jkt)',
    description: 'Logout usando un par de claves nuevo. aegis compara jkt contra la sesión y rechaza con 401 Phantom session mismatch.',
  },
  {
    key: 'meInvalidPhantom',
    label: '/users/me con Phantom Token inválido',
    description: 'GET /users/me con un UUID malformado o sin sesión en Redis. aegis responde 401 Unauthorized.',
  },
  {
    key: 'meDifferentDpop',
    label: '/users/me con DPoP diferente (jkt)',
    description: 'Phantom válido + DPoP firmado con un jkt distinto. aegis responde 401 DPOP_JKT_MISMATCH.',
  },
  {
    key: 'introspectInvalidToken',
    label: 'Introspect con token inválido',
    description: 'UUID v4 que no existe en Redis. aegis responde 200 con active:false.',
  },
  {
    key: 'introspectExpiredToken',
    label: 'Introspect con token expirado',
    description: 'Espera a que el phantom access_token pase su expires_in y luego introspecta. aegis responde active:false.',
  },
];

export function SecurityTestView({ onResult, onLoadingChange, result }: Props) {
  const [loading, setLoading] = useState<string | null>(null);

  const run = async (key: string) => {
    const runner = RUNNERS[key];
    if (!runner) return;
    setLoading(key);
    onLoadingChange?.(true);
    onResult(null);
    const res = await runner();
    onResult(res);
    setLoading(null);
    onLoadingChange?.(false);
  };

  return (
    <div className="security-grid">
      {SCENARIOS.map((s) => (
        <button
          key={s.key}
          className={`scenario ${loading === s.key ? 'loading' : ''}`}
          onClick={() => run(s.key)}
          disabled={!!loading}
        >
          <span className="scenario-label">{s.label}</span>
          <span className="scenario-description">{s.description}</span>
          {loading === s.key && <span className="badge loading">running</span>}
          {!loading && result && (
            <span className={`badge ${result.ok ? 'ok' : 'fail'}`}>
              {result.ok ? 'accepted' : 'rejected'}
            </span>
          )}
        </button>
      ))}
      <p className="muted small">
        Los escenarios 1-4 asumen que ya iniciaste sesión en la pestaña "2. Login". El escenario
        6 puede requerir esperar a que expire la sesión (≤ 5 min según la config de aegis).
      </p>
    </div>
  );
}

const RUNNERS: Record<string, () => Promise<ActionResult<unknown>>> = {
  loginValid: async () => {
    const session = getSession();
    if (!session || !session.channelId || !session.username) {
      return {
        ok: false,
        error:
          'No hay credenciales cacheadas en la sesión. Inicia sesión manualmente en la pestaña "2. Login" al menos una vez para guardar username + channelId.',
        log: [],
      };
    }
    // We use a placeholder password — the user only needs to confirm the
    // happy-path plumbing works. If the password is wrong aegis will 401 in
    // Keycloak (post-DPoP).
    return actionLogin({
      country: session.country,
      clientId: session.channelId,
      username: session.username,
      password: 'SecurityTestPlaceholder',
      alg: session.dpopAlg,
    });
  },

  dpopTamperHtu: async () => {
    const session = getSession();
    if (!session || !session.channelId || !session.username) {
      return {
        ok: false,
        error: 'No hay sesión activa. Inicia sesión en la pestaña "2. Login" primero.',
        log: [],
      };
    }
    return actionLogin({
      country: session.country,
      clientId: session.channelId,
      username: session.username,
      // Password real no es necesario: el guard rechaza ANTES de llegar a Keycloak.
      password: 'TamperedPasswordForDPoPTest',
      alg: session.dpopAlg,
      proofOptions: {
        tamper: ({ payload }) => {
          // Mutamos el payload antes de firmar -> htu falso.
          payload.htu = 'https://aegis-dev.preprodcxr.co/api/v1/co/public/logout';
        },
      },
    });
  },

  logoutDifferentDpop: async () => {
    const session = getSession();
    if (!session || !session.accessToken) {
      return { ok: false, error: 'No hay phantom session. Inicia sesión primero.', log: [] };
    }
    const altPair: DpopKeyPair = await generateDpopKeyPair(session.dpopAlg);
    return actionLogout({ proofOptions: { overrideKeyPair: altPair } });
  },

  meInvalidPhantom: async () => {
    const kp = getDpopKeyPair();
    if (!kp) {
      return { ok: false, error: 'No hay DPoP keypair. Inicia sesión primero.', log: [] };
    }
    return actionGetMeWithToken('not-a-uuid', kp);
  },

  meDifferentDpop: async () => {
    const session = getSession();
    if (!session || !session.accessToken) {
      return { ok: false, error: 'No hay phantom session. Inicia sesión primero.', log: [] };
    }
    const altPair: DpopKeyPair = await generateDpopKeyPair(session.dpopAlg);
    return actionGetMe({ proofOptions: { overrideKeyPair: altPair } });
  },

  introspectInvalidToken: async () => {
    return actionIntrospect({ token: '00000000-0000-4000-8000-000000000000' });
  },

  introspectExpiredToken: async () => {
    const session = getSession();
    if (!session || !session.accessToken || !session.expiresAt) {
      return {
        ok: false,
        error:
          'No hay phantom session, o no ha expirado todavía. Inicia sesión y espera al expires_in (típicamente 300s).',
        log: [],
      };
    }
    const remainingMs = session.expiresAt - Date.now();
    if (remainingMs > 0) {
      const seconds = Math.ceil(remainingMs / 1000) + 1;
      return {
        ok: false,
        error: `La sesión aún no ha expirado (faltan ${seconds}s). Espera o usa el escenario "Introspect con token inválido" para forzar active:false.`,
        log: [],
      };
    }
    return actionIntrospect({ token: session.accessToken });
  },
};
