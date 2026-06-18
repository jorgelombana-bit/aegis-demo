import {
  buildDpopAuthHeader,
  buildDpopLoginHeader,
  createUser,
  getMe,
  introspect,
  login,
  logout,
} from './api';
import { buildDpopProof, htuForAegis, type BuiltDpopProof, type DpopKeyPair } from './dpop';
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

/**
 * The EXACT HTTP request that was sent to aegis-core. Captured by every action
 * so the ResponsePanel can render it with all the real values (DPoP JWT,
 * JWE compact, headers, body) and the user can verify 100% what went on the wire.
 */
export type ExecutedRequest = {
  method: string;
  /** Full URL the request was sent to. For proxied endpoints this is the proxied target. */
  url: string;
  /** Final headers as they were sent (including DPoP, Authorization, etc.). */
  headers: Record<string, string>;
  /** Raw DPoP compact JWT (header.payload.signature), if a DPoP proof was sent. */
  dpopProofJwt?: string;
  /** Decoded DPoP header (for display). */
  dpopHeader?: Record<string, unknown>;
  /** Decoded DPoP payload (for display). */
  dpopPayload?: Record<string, unknown>;
  /** Compact JWE string (header.encrypted_key.iv.ciphertext.tag), if a JWE body was sent. */
  jweCompact?: string;
  /** Plaintext that the JWE encrypts (for display — shows exactly what aegis-core will see). */
  jwePlaintext?: Record<string, unknown>;
  /** Plain JSON body sent on the wire (for endpoints without JWE, e.g. logout, introspect, refresh). */
  rawBody?: Record<string, unknown>;
  /** Same as `rawBody` but as a string (preserves key order and exact formatting). */
  rawBodyBytes?: string;
};

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
  /** The actual HTTP request that was sent. Populated by every action. */
  executedRequest?: ExecutedRequest;
};

export type { DpopKeyPair, BuiltDpopProof };

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
): Promise<BuiltDpopProof & { wireHeader: string }> {
  const keyPair = opts.overrideKeyPair ?? getDpopKeyPair();
  if (!keyPair) throw new Error('No DPoP key pair. Run Create User or Login first to initialize one.');

  const { jti, iat } = newAntiReplayJti();
  const built = await buildDpopProof({
    keyPair,
    htm,
    htu: htuForAegis(htuPath),
    jti,
    iat,
    tamper: opts.tamper,
  });
  return { ...built, wireHeader: buildDpopLoginHeader(built.proofJwt) };
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
): Promise<BuiltDpopProof & { wireHeader: string }> {
  const keyPair = opts.overrideKeyPair ?? getDpopKeyPair();
  if (!keyPair) throw new Error('No DPoP key pair. Run Create User or Login first to initialize one.');

  const { jti, iat } = newAntiReplayJti();
  const built = await buildDpopProof({
    keyPair,
    htm,
    htu: htuForAegis(htuPath),
    phantomAccessToken,
    jti,
    iat,
    tamper: opts.tamper,
  });
  return { ...built, wireHeader: buildDpopAuthHeader(built.proofJwt) };
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
    const jti = Math.floor(Date.now() / 1000);
    // Note: `user_identifier` is NOT included inside the JWE — the server's
    // JweRegistrationDecryptInterceptor (aegis/src/shared/crypto/interceptors/
    // jwe-registration-decrypt.interceptor.ts:115-155) doesn't read it from
    // the JWE, and its body rewrite at line 174-178 overwrites the body's
    // `user_identifier` with the value from the outer envelope anyway.
    const securePlaintext = {
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

    // Note: `device_context` is NOT included in the outer body. The
    // register-self-service-user handler (aegis/src/modules/user/application/
    // handler/register-self-service-user.handler.ts:28-69) reads sourceIp
    // and userAgent from the Fastify request (ip + user-agent header), not
    // from the body. The interceptor accepts `device_context` if present
    // (jwe-registration-decrypt.interceptor.ts:73-80) but never requires it.
    const executedRequest: ExecutedRequest = {
      method: 'POST',
      url: htuForAegis(`/api/v1/${input.country}/public/user`),
      headers: {
        'Content-Type': 'application/json',
      },
      jweCompact: securePayload,
      jwePlaintext: {
        ...securePlaintext,
        userData: { ...securePlaintext.userData, password: '***' },
      },
      rawBody: {
        user_identifier: input.email,
        secure_payload: securePayload,
      },
      rawBodyBytes: JSON.stringify(
        {
          user_identifier: input.email,
          secure_payload: securePayload,
        },
        null,
        2,
      ),
    };

    const res = await createUser({
      country: input.country,
      clientId: input.clientId,
      username: input.username,
      email: input.email,
      password: input.password,
      securePayload,
    });

    log.push(`POST /api/v1/${input.country}/public/user -> HTTP ${res.status}`);
    if (res.ok) {
      return { ok: true, data: res.data, log, httpStatus: res.status, executedRequest };
    }
    return { ok: false, error: describeError(res.data, res.status), data: res.data as never, log, httpStatus: res.status, executedRequest };
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
    // Note: `user_identifier` is NOT included inside the JWE — the server's
    // JweDecryptInterceptor (aegis/src/shared/crypto/interceptors/jwe-decrypt.
    // interceptor.ts:144-152) only validates credentials + anti_replay from
    // the JWE, and its body rewrite at line 175-179 overwrites the body's
    // `user_identifier` with the value from the outer envelope.
    const securePlaintext = {
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

    const built = await buildLoginProof(
      'POST',
      `/api/v1/${input.country}/public/login`,
      input.proofOptions
    );
    log.push(`DPoP proof built (alg=${input.proofOptions?.overrideKeyPair?.alg ?? input.alg}, jkt=${built.jkt})`);
    log.push(`DPoP header value = "DPoP <jwt>" (DpopLoginGuard expects prefix)`);

    const executedRequest: ExecutedRequest = {
      method: 'POST',
      url: htuForAegis(`/api/v1/${input.country}/public/login`),
      headers: {
        'Content-Type': 'application/json',
        DPoP: built.wireHeader,
      },
      dpopProofJwt: built.proofJwt,
      dpopHeader: built.header,
      dpopPayload: built.payload,
      jweCompact: securePayload,
      jwePlaintext: {
        ...securePlaintext,
        credentials: { ...securePlaintext.credentials, pass: '***' },
      },
      rawBody: {
        user_identifier: input.username,
        device_context: ctx,
        secure_payload: securePayload,
      },
      rawBodyBytes: JSON.stringify(
        {
          user_identifier: input.username,
          device_context: ctx,
          secure_payload: securePayload,
        },
        null,
        2,
      ),
    };

    const res = await login({
      country: input.country,
      clientId: input.clientId,
      username: input.username,
      password: input.password,
      deviceContext: ctx,
      securePayload,
      dpopLoginHeader: built.wireHeader,
    });

    log.push(`POST /api/v1/${input.country}/public/login -> HTTP ${res.status}`);

    if (res.ok) {
      const data = res.data as PublicHumanLoginResponse;
      setCredentials(input.username, input.clientId, input.password);
      setPhantomTokens(data.access_token, data.refresh_token, data.expires_in);
      log.push(`phantom access_token  = ${data.access_token}`);
      log.push(`phantom refresh_token = ${data.refresh_token}`);
      log.push(`expires_in            = ${data.expires_in}s`);
      return { ok: true, data, log, httpStatus: res.status, executedRequest };
    }
    return { ok: false, error: describeError(res.data, res.status), data: res.data as never, log, httpStatus: res.status, executedRequest };
  } catch (err) {
    return { ok: false, error: errorMessage(err), data: undefined, log };
  }
}

// =============================================================================
// 3. Logout (DpopAuthGuard + Bearer Authorization; raw DPoP proof with `ath`;
//          body is a plain JSON object `{ refresh_token: "..." }` — no JWE envelope).
// =============================================================================
export type LogoutInput = {
  proofOptions?: BuildProofOptions;
  /** Caso 5 / Modo Test: no borrar tokens locales (aegis devuelve 204 aunque el guard falle). */
  preserveLocalSession?: boolean;
};

export async function actionLogout(input: LogoutInput = {}): Promise<ActionResult<null>> {
  const log: ActionLog = [];
  try {
    const session = getSession();
    if (!session) throw new Error('No active session. Login first.');
    if (!session.accessToken || !session.refreshToken) {
      throw new Error('Incomplete session. Login first.');
    }

    // Logout now uses DpopAuthGuard (manually invoked inside the handler) + Bearer.
    // The DPoP proof must include `ath` and the wire header is the raw compact JWT
    // (NO `DPoP ` prefix — that prefix is only for DpopLoginGuard on login).
    const built = await buildAuthProof(
      'POST',
      `/api/v1/${session.country}/public/logout`,
      session.accessToken,
      input.proofOptions
    );
    log.push(`DPoP proof built (jkt=${input.proofOptions?.overrideKeyPair?.jkt ?? built.jkt}, with ath)`);
    log.push(`DPoP header value = <raw jwt> (DpopAuthGuard expects raw compact JWT, no prefix)`);
    log.push(`Authorization header = "Bearer <phantomAccessToken>" (extractBearerTokenFromRequest exige scheme Bearer)`);
    log.push(`Body: { refresh_token: "<phantom-refresh-uuid>" }  (JSON plano, sin JWE, sin device_context, sin anti_replay)`);

    const executedRequest: ExecutedRequest = {
      method: 'POST',
      url: htuForAegis(`/api/v1/${session.country}/public/logout`),
      headers: {
        Authorization: `Bearer ${session.accessToken}`,
        'Content-Type': 'application/json',
        DPoP: built.proofJwt,
      },
      dpopProofJwt: built.proofJwt,
      dpopHeader: built.header,
      dpopPayload: built.payload,
      rawBody: { refresh_token: session.refreshToken },
      rawBodyBytes: JSON.stringify({ refresh_token: session.refreshToken }, null, 2),
    };

    const res = await logout({
      country: session.country,
      refreshToken: session.refreshToken,
      phantomAccessToken: session.accessToken,
      dpopProofJwt: built.proofJwt,
    });

    log.push(`POST /api/v1/${session.country}/public/logout -> HTTP ${res.status}`);

    if (res.ok) {
      if (!input.preserveLocalSession) {
        clearPhantomTokens();
      } else {
        log.push('Sesión local preservada (logout de prueba; aegis puede responder 204 sin revocar).');
      }
      return { ok: true, data: null, log, httpStatus: res.status, executedRequest };
    }
    return { ok: false, error: describeError(res.data, res.status), data: res.data as never, log, httpStatus: res.status, executedRequest };
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

    const executedRequest: ExecutedRequest = {
      method: 'POST',
      url: '/internal/token/introspect  (Vite proxy → /api/v1/internal/token/introspect)',
      headers: {
        'X-Internal-API-Key': '<server-side, inyectado por el Vite proxy>',
        'X-Caller-Service': 'aegis-demo-ui',
        'Content-Type': 'application/json',
      },
      rawBody: { token: input.token },
      rawBodyBytes: JSON.stringify({ token: input.token }, null, 2),
    };

    const res = await introspect(input.token);
    log.push(`HTTP ${res.status}`);
    if (res.ok) {
      const data = unwrapIntrospectPayload(res.data);
      if (!data) {
        return { ok: false, error: 'Unexpected introspect response shape', data: res.data as never, log, httpStatus: res.status, executedRequest };
      }
      log.push(`active=${String(data.active)}`);
      const session = getSession();
      if (session?.dpopJkt && data.active && data.dpop_jkt) {
        const match = data.dpop_jkt === session.dpopJkt;
        log.push(
          match
            ? `Phantom↔DPoP: OK (introspect dpop_jkt = session jkt = ${session.dpopJkt})`
            : `Phantom↔DPoP: MISMATCH (introspect=${data.dpop_jkt}, session=${session.dpopJkt})`
        );
      }
      // The introspect endpoint always returns HTTP 200, but the SEMANTIC outcome
      // is `active: true` (token valid) or `active: false` (token invalid / unknown).
      // We surface the semantic result via `ok` so the Security Test can assert
      // the test condition correctly.
      return { ok: data.active === true, data, log, httpStatus: res.status, executedRequest };
    }
    return { ok: false, error: describeError(res.data, res.status), data: res.data as never, log, httpStatus: res.status, executedRequest };
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

    const built = await buildAuthProof(
      'GET',
      `/api/v1/users/me`,
      session.accessToken,
      input.proofOptions
    );
    log.push(`DPoP proof built (jkt=${input.proofOptions?.overrideKeyPair?.jkt ?? built.jkt})`);
    log.push(`DPoP proof includes ath = base64url(sha256(phantomAccessToken))`);
    log.push(`Authorization header = "DPoP <phantomAccessToken>" (PhantomTokenGuard requires DPoP scheme)`);

    const executedRequest: ExecutedRequest = {
      method: 'GET',
      url: htuForAegis('/api/v1/users/me'),
      headers: {
        Authorization: `DPoP ${session.accessToken}`,
        DPoP: built.proofJwt,
      },
      dpopProofJwt: built.proofJwt,
      dpopHeader: built.header,
      dpopPayload: built.payload,
    };

    const res = await getMe({ phantomAccessToken: session.accessToken, dpopProofJwt: built.proofJwt });
    log.push(`GET /api/v1/users/me -> HTTP ${res.status}`);

    if (res.ok) {
      const env = res.data as { data?: PhantomUserMeResponse };
      return { ok: true, data: env.data, log, httpStatus: res.status, executedRequest };
    }
    return { ok: false, error: describeError(res.data, res.status), data: res.data as never, log, httpStatus: res.status, executedRequest };
  } catch (err) {
    return { ok: false, error: errorMessage(err), data: undefined, log };
  }
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

function unwrapIntrospectPayload(payload: unknown): IntrospectTokenResponse | null {
  if (!payload || typeof payload !== 'object') return null;
  const row = payload as Record<string, unknown>;
  if (typeof row.active === 'boolean') return row as IntrospectTokenResponse;
  const nested = row.data;
  if (nested && typeof nested === 'object' && typeof (nested as IntrospectTokenResponse).active === 'boolean') {
    return nested as IntrospectTokenResponse;
  }
  return null;
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
