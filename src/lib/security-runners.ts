import { actionIntrospect, actionLogout, type ActionResult } from './actions';
import { buildDpopAuthHeader, getMe, type AegisCallResult } from './api';
import { buildDpopProof, htuForAegis, generateDpopKeyPair, type DpopKeyPair } from './dpop';
import { getDpopKeyPair, getSession, newAntiReplayJti } from './session';
import type { IntrospectTokenResponse } from './types';

export async function actionGetMeWithToken(
  phantomAccessToken: string,
  overrideKeyPair?: DpopKeyPair
): Promise<ActionResult<unknown>> {
  const log: string[] = [];
  try {
    const keyPair = overrideKeyPair ?? getDpopKeyPair();
    if (!keyPair) throw new Error('No DPoP keypair. Run tab 2 first.');

    const { jti, iat } = newAntiReplayJti();
    const built = await buildDpopProof({
      keyPair,
      htm: 'GET',
      htu: htuForAegis('/api/v1/users/me'),
      phantomAccessToken,
      jti,
      iat,
    });
    log.push(`DPoP proof built (jkt=${keyPair.jkt}, with ath)`);

    const res: AegisCallResult<unknown> = await getMe({
      phantomAccessToken,
      dpopProofJwt: buildDpopAuthHeader(built.proofJwt),
    });
    log.push(`GET /api/v1/users/me -> HTTP ${res.status}`);

    if (res.ok) {
      return { ok: true, data: res.data, log, httpStatus: res.status };
    }
    return { ok: false, error: describeError(res.data, res.status), data: res.data as never, log, httpStatus: res.status };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err), log };
  }
}

const INVALID_PHANTOM_UUID = '00000000-0000-4000-8000-000000000000';

export async function runLogoutWithWrongDpop(): Promise<ActionResult<unknown>> {
  const session = getSession();
  const keyPair = getDpopKeyPair();
  if (!session?.accessToken || !keyPair) {
    return { ok: false, error: 'Inicia sesión en tab 2 primero.', log: [] };
  }

  const savedAccess = session.accessToken;
  const altPair = await generateDpopKeyPair(session.dpopAlg);
  const log: string[] = [];

  log.push(`Intento logout con jkt incorrecto (alt=${altPair.jkt}, sesión=${keyPair.jkt})`);

  const logoutRes = await actionLogout({
    proofOptions: { overrideKeyPair: altPair },
    preserveLocalSession: true,
  });
  log.push(...logoutRes.log);

  // aegis-core devuelve HTTP 204 aunque el DPoP sea inválido (el guard falla pero el controller
  // traga el error). La prueba real es: ¿la sesión phantom sigue activa?
  log.push('--- verificación: introspect del access_token ---');
  const introRes = await actionIntrospect({ token: savedAccess });
  log.push(...introRes.log);

  const introData = unwrapIntrospect(introRes.data);
  const introActive = introRes.ok && introData?.active === true;
  if (introRes.ok) {
    log.push(`introspect active=${String(introData?.active)}`);
  } else {
    log.push(
      `introspect falló (HTTP ${introRes.httpStatus ?? '?'}). ¿VITE_AEGIS_INTERNAL_API_KEY en .env y dev server reiniciado?`
    );
  }

  log.push('--- verificación: GET /users/me con Phantom + DPoP originales ---');
  const meRes = await actionGetMeWithToken(savedAccess, keyPair);
  log.push(...meRes.log);

  // aegis responde 204 siempre; la prueba pasa si la sesión phantom sigue usable.
  const sessionStillActive = introActive || meRes.ok;

  if (sessionStillActive) {
    log.push('Caso 5 OK: logout con DPoP distinto no revocó la sesión phantom.');
    if (introActive && meRes.ok) {
      log.push('Confirmado por introspect (active:true) y GET /users/me (200).');
    } else if (introActive) {
      log.push('Confirmado por introspect (active:true).');
    } else {
      log.push('Confirmado por GET /users/me (200).');
    }
    return {
      ok: true,
      data: { introspect: introData, me: meRes.data },
      log,
      httpStatus: logoutRes.httpStatus,
    };
  }

  const details: string[] = [];
  if (introRes.ok) {
    details.push(`introspect active:${String(introData?.active)}`);
  } else {
    details.push(`introspect: ${introRes.error ?? `HTTP ${introRes.httpStatus ?? '?'}`}`);
  }
  details.push(`GET /users/me: HTTP ${meRes.httpStatus ?? '?'}`);

  return {
    ok: false,
    error: `La sesión phantom quedó inactiva tras logout con DPoP incorrecto (${details.join('; ')}). ¿Hiciste logout real en tab 3 antes?`,
    data: { introspect: introData, me: meRes.data },
    log,
    httpStatus: logoutRes.httpStatus,
  };
}

function unwrapIntrospect(payload: unknown): IntrospectTokenResponse | undefined {
  if (!payload || typeof payload !== 'object') return undefined;
  const row = payload as Record<string, unknown>;
  if (typeof row.active === 'boolean') return row as IntrospectTokenResponse;
  const nested = row.data;
  if (nested && typeof nested === 'object' && typeof (nested as IntrospectTokenResponse).active === 'boolean') {
    return nested as IntrospectTokenResponse;
  }
  return undefined;
}

export function isIntrospectInactive(result: ActionResult<IntrospectTokenResponse>): boolean {
  // `result.ok` is now `active === true` (set by `actionIntrospect`). The introspect
  // semantically rejected the token iff `ok` is false AND the body has `active: false`.
  const data = unwrapIntrospect(result.data);
  return !result.ok && data?.active === false;
}

export { INVALID_PHANTOM_UUID };

function describeError(payload: unknown, status: number): string {
  if (payload && typeof payload === 'object') {
    const env = payload as { error_description?: string; error?: string; message?: string | string[] };
    if (env.error_description) return env.error_description;
    if (env.error) return env.error;
    if (typeof env.message === 'string') return env.message;
    if (Array.isArray(env.message)) return env.message.join(', ');
  }
  return `HTTP ${status}`;
}
