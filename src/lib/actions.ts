import {
  buildDpopAuthHeader,
  buildDpopLoginHeader,
  createUser,
  getMe,
  introspect,
  login,
  logout,
  refresh,
} from './api';
import { buildDpopProof, htuForAegis, type DpopKeyPair } from './dpop';
import { encryptJwe } from './jwe';
import {
  clearPhantomTokens,
  fingerprintFromBrowser,
  getDpopKeyPair,
  getSession,
  initSession,
  newAntiReplayJti,
  rotateDpopKeyPair,
  setCredentials,
  setPhantomTokens,
} from './session';
import type { DpopAlg, IntrospectTokenResponse, PhantomUserMeResponse, PublicHumanLoginResponse } from './types';

export type ActionLog = string[];

export type ActionResult<T = unknown> = {
  ok: boolean;
  data?: T;
  /**
   * Human summary of the failure (one-line message). If the upstream error body is
   * structured, the full body is also exposed via `data` and rendered as JSON.
   */
  error?: string;
  log: ActionLog;
  httpStatus?: number;
};

export type { DpopKeyPair } from './dpop';

type BuildProofOptions = {
  tamper?: (unsigned: { header: Record<string, unknown>; payload: Record<string, unknown> }) => void;
  overrideKeyPair?: DpopKeyPair;
};

/**
 * DpopLoginGuard is in front of `/public/login` only. The proof must NOT
 * include `ath`.
 */
async function buildLoginProof(
  htm: 'POST',
  htuPath: string,
  opts: BuildProofOptions = {}
): Promise<{ proofJwt: string; header: string; jti: string; iat: number; jkt: string }> {
  const keyPair = opts.overrideKeyPair ?? getDpopKeyPair();
  if (!keyPair) throw new Error('No DPoP key pair. Run Create User or Login first to initialize one.');

  const { jti, iat } = newAntiReplayJti();
  const proofJwt = await buildDpopProof({
    keyPair,
    htm,
    htu: htuForAegis(htuPath),
    jti,
    iat,
    tamper: opts.tamper,
  });
  return {
    proofJwt,
    header: buildDpopLoginHeader(proofJwt),
    jti,
    iat,
    jkt: keyPair.jkt,
  };
}

/**
 * DpopAuthGuard is in front of `/users/me` and `/auth/refresh-token`. The proof
 * MUST include `ath = base64url(sha256(phantomAccessToken))`.
 */
async function buildAuthProof(
  htm: 'GET' | 'POST',
  htuPath: string,
  phantomAccessToken: string,
  opts: BuildProofOptions = {}
): Promise<{ proofJwt: string; header: string; jti: string; iat: number; jkt: string }> {
  const keyPair = opts.overrideKeyPair ?? getDpopKeyPair();
  if (!keyPair) throw new Error('No DPoP key pair. Run Create User or Login first to initialize one.');

  const { jti, iat } = newAntiReplayJti();
  const proofJwt = await buildDpopProof({
    keyPair,
    htm,
    htu: htuForAegis(htuPath),
    phantomAccessToken,
    jti,
    iat,
    tamper: opts.tamper,
  });
  return {
    proofJwt,
    header: buildDpopAuthHeader(proofJwt),
    jti,
    iat,
    jkt: keyPair.jkt,
  };
}

export async function ensureSession(country: string, alg: DpopAlg): Promise<void> {
  if (!getSession()) {
    await initSession(country, alg);
    return;
  }
  // Login always rotates the DPoP key pair (see LoginView). Re-init if the pair
  // was never stored (older sessions) or the algorithm changed.
  if (!getDpopKeyPair() || getSession()?.dpopAlg !== alg) {
    await rotateDpopKeyPair(alg);
  }
}

// =============================================================================
// 1. Create User
// =============================================================================
export type CreateUserInput = {
  country: string;
  clientId: string;
  username: string;
  email: string;
  password: string;
};

export async function actionCreateUser(input: CreateUserInput): Promise<ActionResult<unknown>> {
  const log: ActionLog = [];
  try {
    const ctx = fingerprintFromBrowser();
    log.push(`device_context.fingerprint = ${ctx.fingerprint}`);
    log.push(`device_context.userAgent   = ${ctx.userAgent.slice(0, 60)}...`);

    const jti = Math.floor(Date.now() / 1000);
    const securePlaintext = {
      user_identifier: input.email,
      clientId: input.clientId,
      userData: { username: input.username, email: input.email, password: input.password },
      credentials: { user_check: input.email },
      anti_replay: { iat: jti, jti: crypto.randomUUID() },
    };
    log.push(`secure_payload (plaintext) = ${JSON.stringify({
      ...securePlaintext,
      userData: { ...securePlaintext.userData, password: '***' },
    })}`);

    const securePayload = await encryptJwe(input.country, securePlaintext);
    log.push(`secure_payload (JWE, first 40 chars) = ${securePayload.slice(0, 40)}...`);

    const res = await createUser({
      country: input.country,
      clientId: input.clientId,
      username: input.username,
      email: input.email,
      password: input.password,
      deviceContext: ctx,
      securePayload,
    });

    log.push(`POST /api/v1/${input.country}/public/user -> HTTP ${res.status}`);
    if (res.ok) {
      return { ok: true, data: res.data, log, httpStatus: res.status };
    }
    return { ok: false, error: describeError(res.data, res.status), data: res.data as never, log, httpStatus: res.status };
  } catch (err) {
    return { ok: false, error: errorMessage(err), data: undefined, log };
  }
}

// =============================================================================
// 2. Login (DpopLoginGuard: DPoP header = `DPoP <jwt>`, no ath)
// =============================================================================
export type LoginInput = {
  country: string;
  clientId: string;
  username: string;
  password: string;
  alg: DpopAlg;
  proofOptions?: BuildProofOptions;
};

export async function actionLogin(input: LoginInput): Promise<ActionResult<PublicHumanLoginResponse>> {
  const log: ActionLog = [];
  try {
    await ensureSession(input.country, input.alg);
    // Fresh DPoP key per login attempt (binds a new jkt to the phantom session).
    await rotateDpopKeyPair(input.alg);
    const ctx = fingerprintFromBrowser();

    const { jti, iat } = newAntiReplayJti();
    const securePlaintext = {
      user_identifier: input.username,
      credentials: {
        clientId: input.clientId,
        pass: input.password,
        user_check: input.username,
      },
      anti_replay: { iat, jti },
    };
    log.push(`secure_payload (plaintext, redacted) = ${JSON.stringify({
      ...securePlaintext,
      credentials: { ...securePlaintext.credentials, pass: '***' },
    })}`);

    const securePayload = await encryptJwe(input.country, securePlaintext);
    log.push(`secure_payload (JWE, first 40 chars) = ${securePayload.slice(0, 40)}...`);

    const { header, jkt } = await buildLoginProof(
      'POST',
      `/api/v1/${input.country}/public/login`,
      input.proofOptions
    );
    log.push(`DPoP proof built (alg=${input.proofOptions?.overrideKeyPair?.alg ?? input.alg}, jkt=${jkt})`);
    log.push(`DPoP header value = "DPoP <jwt>" (DpopLoginGuard expects prefix)`);

    const res = await login({
      country: input.country,
      clientId: input.clientId,
      username: input.username,
      password: input.password,
      deviceContext: ctx,
      securePayload,
      dpopLoginHeader: header,
    });

    log.push(`POST /api/v1/${input.country}/public/login -> HTTP ${res.status}`);

    if (res.ok) {
      const data = res.data as PublicHumanLoginResponse;
      setCredentials(input.username, input.clientId);
      setPhantomTokens(data.access_token, data.refresh_token, data.expires_in);
      log.push(`phantom access_token  = ${data.access_token}`);
      log.push(`phantom refresh_token = ${data.refresh_token}`);
      log.push(`expires_in            = ${data.expires_in}s`);
      return { ok: true, data, log, httpStatus: res.status };
    }
    return { ok: false, error: describeError(res.data, res.status), data: res.data as never, log, httpStatus: res.status };
  } catch (err) {
    return { ok: false, error: errorMessage(err), data: undefined, log };
  }
}

// =============================================================================
// 3. Logout (DpopAuthGuard + Bearer Authorization + ath in DPoP proof)
// =============================================================================
export type LogoutInput = {
  proofOptions?: BuildProofOptions;
};

export async function actionLogout(input: LogoutInput = {}): Promise<ActionResult<null>> {
  const log: ActionLog = [];
  try {
    const session = getSession();
    if (!session) throw new Error('No active session. Login first.');
    if (!session.accessToken || !session.refreshToken || !session.username || !session.channelId) {
      throw new Error('Incomplete session. Login first.');
    }
    const ctx = fingerprintFromBrowser();

    const { jti, iat } = newAntiReplayJti();
    const securePlaintext = {
      credentials: {
        clientId: session.channelId,
        pass: session.refreshToken,
        user_check: session.username,
      },
      anti_replay: { iat, jti },
    };
    log.push(`secure_payload.pass = phantom refresh_token (UUID v4)`);
    const securePayload = await encryptJwe(session.country, securePlaintext);
    log.push(`secure_payload (JWE, first 40 chars) = ${securePayload.slice(0, 40)}...`);

    const { header, jkt } = await buildAuthProof(
      'POST',
      `/api/v1/${session.country}/public/logout`,
      session.accessToken,
      input.proofOptions
    );
    log.push(`DPoP proof built (jkt=${input.proofOptions?.overrideKeyPair?.jkt ?? jkt})`);
    log.push(`DPoP proof includes ath = base64url(sha256(phantomAccessToken))`);
    log.push(`Authorization header = "Bearer <phantomAccessToken>" (DpopAuthGuard accepts Bearer; extractBearerTokenFromRequest requires it)`);

    const res = await logout({
      country: session.country,
      clientId: session.channelId,
      username: session.username,
      phantomRefreshToken: session.refreshToken,
      deviceContext: ctx,
      securePayload,
      dpopProofJwt: header,
      phantomAccessToken: session.accessToken,
    });

    log.push(`POST /api/v1/${session.country}/public/logout -> HTTP ${res.status}`);

    if (res.ok) {
      const revokedAccess = session.accessToken;
      clearPhantomTokens();
      log.push('Local phantom tokens cleared from demo session.');

      const intro = await introspect(revokedAccess);
      if (intro.ok && intro.data && typeof intro.data === 'object' && 'active' in intro.data) {
        const active = (intro.data as IntrospectTokenResponse).active;
        log.push(`Post-logout introspect: active=${active}`);
        if (active) {
          log.push(
            'Note: aegis-core returns HTTP 204 on logout but may keep the phantom Redis session until TTL; introspect can still show active:true.'
          );
        }
      }

      return { ok: true, data: null, log, httpStatus: res.status };
    }
    return { ok: false, error: describeError(res.data, res.status), data: res.data as never, log, httpStatus: res.status };
  } catch (err) {
    return { ok: false, error: errorMessage(err), data: undefined, log };
  }
}

// =============================================================================
// 4. Introspect
// =============================================================================
export type IntrospectInput = {
  token: string;
};

export async function actionIntrospect(input: IntrospectInput): Promise<ActionResult<IntrospectTokenResponse>> {
  const log: ActionLog = [];
  try {
    log.push(`X-Internal-API-Key injected by Vite dev proxy (server-side, from VITE_AEGIS_INTERNAL_API_KEY)`);
    log.push(`X-Caller-Service = aegis-demo-ui`);
    log.push(`POST /api/v1/internal/token/introspect (browser -> /internal/* -> proxy -> aegis-core)`);
    const res = await introspect(input.token);
    log.push(`HTTP ${res.status}`);
    if (res.ok) {
      return { ok: true, data: res.data as IntrospectTokenResponse, log, httpStatus: res.status };
    }
    return { ok: false, error: describeError(res.data, res.status), data: res.data as never, log, httpStatus: res.status };
  } catch (err) {
    return { ok: false, error: errorMessage(err), data: undefined, log };
  }
}

// =============================================================================
// 5. /users/me (DpopAuthGuard: DPoP header = raw jwt, with ath)
// =============================================================================
export type GetMeInput = {
  proofOptions?: BuildProofOptions;
};

export async function actionGetMe(input: GetMeInput = {}): Promise<ActionResult<PhantomUserMeResponse>> {
  const log: ActionLog = [];
  try {
    const session = getSession();
    if (!session) throw new Error('No active session. Login first.');
    if (!session.accessToken) throw new Error('No phantom access token. Login first.');

    const { header, jkt } = await buildAuthProof(
      'GET',
      `/api/v1/users/me`,
      session.accessToken,
      input.proofOptions
    );
    log.push(`DPoP proof built (jkt=${input.proofOptions?.overrideKeyPair?.jkt ?? jkt})`);
    log.push(`DPoP proof includes ath = base64url(sha256(phantomAccessToken))`);
    log.push(`Authorization header = "DPoP <phantomAccessToken>" (PhantomTokenGuard requires DPoP scheme)`);

    const res = await getMe({ phantomAccessToken: session.accessToken, dpopProofJwt: header });
    log.push(`GET /api/v1/users/me -> HTTP ${res.status}`);

    if (res.ok) {
      const env = res.data as { data?: PhantomUserMeResponse };
      return { ok: true, data: env.data, log, httpStatus: res.status };
    }
    return { ok: false, error: describeError(res.data, res.status), data: res.data as never, log, httpStatus: res.status };
  } catch (err) {
    return { ok: false, error: errorMessage(err), data: undefined, log };
  }
}

// =============================================================================
// 6. Refresh (DpopAuthGuard + JSON body)
// =============================================================================
export type RefreshInput = {
  proofOptions?: BuildProofOptions;
};

export async function actionRefresh(input: RefreshInput = {}): Promise<ActionResult<PublicHumanLoginResponse>> {
  const log: ActionLog = [];
  try {
    const session = getSession();
    if (!session) throw new Error('No active session. Login first.');
    if (!session.accessToken || !session.refreshToken || !session.channelId) {
      throw new Error('Incomplete session. Login first.');
    }

    const { header, jkt } = await buildAuthProof(
      'POST',
      `/api/v1/auth/refresh-token`,
      session.accessToken,
      input.proofOptions
    );
    log.push(`DPoP proof built (jkt=${input.proofOptions?.overrideKeyPair?.jkt ?? jkt}, with ath)`);

    const res = await refresh({
      refreshToken: session.refreshToken,
      clientId: session.channelId,
      phantomAccessToken: session.accessToken,
      dpopProofJwt: header,
    });
    log.push(`POST /api/v1/auth/refresh-token -> HTTP ${res.status}`);

    if (res.ok) {
      const data = res.data as PublicHumanLoginResponse;
      // The DPoP key pair is NOT rotated; only tokens are. The jkt is preserved.
      setPhantomTokens(data.access_token, data.refresh_token, data.expires_in);
      log.push(`rotated phantom access_token  = ${data.access_token}`);
      log.push(`rotated phantom refresh_token = ${data.refresh_token}`);
      log.push(`expires_in                    = ${data.expires_in}s`);
      return { ok: true, data, log, httpStatus: res.status };
    }
    return { ok: false, error: describeError(res.data, res.status), data: res.data as never, log, httpStatus: res.status };
  } catch (err) {
    return { ok: false, error: errorMessage(err), data: undefined, log };
  }
}

export async function actionRotateKey(alg: DpopAlg): Promise<void> {
  await rotateDpopKeyPair(alg);
}

// =============================================================================
// helpers
// =============================================================================
function describeError(payload: unknown, status: number): string {
  if (payload && typeof payload === 'object') {
    const env = payload as {
      error_description?: string;
      error?: string;
      message?: string | string[] | unknown[];
    };
    if (env.error_description) return env.error_description;
    if (env.error) return env.error;
    if (typeof env.message === 'string') return env.message;
    if (Array.isArray(env.message)) {
      const first = env.message[0];
      if (first && typeof first === 'object') {
        const ve = first as { property?: string; constraints?: Record<string, string> };
        const constraint = ve.constraints ? Object.values(ve.constraints)[0] : undefined;
        if (ve.property && constraint) return `${ve.property}: ${constraint}`;
        if (constraint) return constraint;
      }
      try {
        return JSON.stringify(env.message);
      } catch {
        return `HTTP ${status}`;
      }
    }
  }
  return `HTTP ${status}`;
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
