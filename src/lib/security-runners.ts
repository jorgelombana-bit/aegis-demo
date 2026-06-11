import { buildDpopAuthHeader, getMe, type AegisCallResult } from './api';
import { buildDpopProof, htuForAegis, type DpopKeyPair } from './dpop';
import { getDpopKeyPair, newAntiReplayJti } from './session';
import type { ActionResult } from './actions';

export async function actionGetMeWithToken(
  phantomAccessToken: string,
  overrideKeyPair?: DpopKeyPair
): Promise<ActionResult<unknown>> {
  const log: string[] = [];
  try {
    const keyPair = overrideKeyPair ?? getDpopKeyPair();
    if (!keyPair) throw new Error('No DPoP keypair. Run tab 2 first.');

    const { jti, iat } = newAntiReplayJti();
    const proofJwt = await buildDpopProof({
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
      dpopProofJwt: buildDpopAuthHeader(proofJwt),
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
