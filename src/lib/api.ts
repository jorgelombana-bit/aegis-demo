import axios from "axios";

import type {
  AegisErrorEnvelope,
  AegisStandardEnvelope,
  EncryptionKeyJwk,
  IntrospectTokenResponse,
  PhantomUserMeResponse,
  PublicHumanLoginResponse,
  PublicHumanRegisterResponse,
} from "./types";

const apiClient = axios.create({
  baseURL: "",
  headers: { "Content-Type": "application/json" },
  // We want full responses even on 4xx/5xx so the UI can render the error envelope.
  validateStatus: () => true,
});

export type AegisCallResult<T> = {
  ok: boolean;
  status: number;
  data: T | AegisErrorEnvelope;
  raw: unknown;
};

export type AuthorizationScheme = "DPoP" | "Bearer";

async function call<T>(
  method: "GET" | "POST" | "PUT" | "DELETE",
  path: string,
  options: { body?: unknown; extraHeaders?: Record<string, string> } = {},
): Promise<AegisCallResult<T>> {
  console.log({
    method,
    url: path,
    data: options.body,
    headers: options.extraHeaders,
    transformResponse: [
      (raw: string) => {
        if (typeof raw !== "string") return raw;
        try {
          return JSON.parse(raw);
        } catch {
          return raw;
        }
      },
    ],
  });
  const response = await apiClient.request<
    AegisStandardEnvelope<T> | AegisErrorEnvelope
  >({
    method,
    url: path,
    data: options.body,
    headers: options.extraHeaders,
    transformResponse: [
      (raw: string) => {
        if (typeof raw !== "string") return raw;
        try {
          return JSON.parse(raw);
        } catch {
          return raw;
        }
      },
    ],
  });

  return {
    ok: response.status >= 200 && response.status < 300,
    status: response.status,
    data: response.data as T,
    raw: response.data,
  };
}

export async function getEncryptionKey(): Promise<EncryptionKeyJwk> {
  const result = await call<AegisStandardEnvelope<EncryptionKeyJwk>>(
    "GET",
    "/api/v1/auth/encryption-key",
  );
  if (!result.ok) {
    throw new Error(`encryption-key failed: HTTP ${result.status}`);
  }
  return (result.data as AegisStandardEnvelope<EncryptionKeyJwk>).data;
}

// =============================================================================
// Build the DPoP/Authorization header values exactly as aegis-core expects them.
//
//   login, logout     -> DpopLoginGuard
//                        DPoP:  "DPoP <jwt>"      (literal `DPoP ` prefix)
//                        Authz: not used for login; `Bearer <access>` for logout
//   /users/me, refresh -> DpopAuthGuard + PhantomTokenGuard
//                        DPoP:  "<jwt>"           (raw, no prefix)
//                        Authz: "DPoP <access>"   (strict `DPoP ` scheme)
// =============================================================================

export function buildDpopLoginHeader(proofJwt: string): string {
  return `DPoP ${proofJwt}`;
}

export function buildDpopAuthHeader(proofJwt: string): string {
  return proofJwt;
}

export function buildPhantomAuthHeader(
  scheme: AuthorizationScheme,
  phantomAccess: string,
): string {
  return `${scheme} ${phantomAccess}`;
}

// =============================================================================
// Endpoint wrappers
// =============================================================================

export type CreateUserRequest = {
  country: string;
  clientId: string;
  username: string;
  email: string;
  password: string;
  securePayload: string;
};

export async function createUser(
  req: CreateUserRequest,
): Promise<AegisCallResult<PublicHumanRegisterResponse>> {
  return call<PublicHumanRegisterResponse>(
    "POST",
    `/api/v1/${req.country}/public/user`,
    {
      body: {
        user_identifier: req.email,
        secure_payload: req.securePayload,
      },
    },
  );
}

export type LoginRequest = {
  country: string;
  clientId: string;
  username: string;
  password: string;
  deviceContext: { fingerprint: string; ip: string; userAgent: string };
  securePayload: string;
  /**
   * Already-wrapped DPoP proof for the DpopLoginGuard.
   * Must be of the form `DPoP <jwt>` (see `buildDpopLoginHeader`).
   */
  dpopLoginHeader: string;
};

export async function login(
  req: LoginRequest,
): Promise<AegisCallResult<PublicHumanLoginResponse>> {
  return call<PublicHumanLoginResponse>(
    "POST",
    `/api/v1/${req.country}/public/login`,
    {
      body: {
        user_identifier: req.username,
        device_context: req.deviceContext,
        secure_payload: req.securePayload,
      },
      extraHeaders: { DPoP: req.dpopLoginHeader },
    },
  );
}

export type LogoutRequest = {
  country: string;
  /**
   * Phantom refresh token returned by POST /{country}/public/login.
   * Sent as a plain string in the body — the logout endpoint no longer
   * expects a JWE envelope, device_context, or anti_replay payload.
   */
  refreshToken: string;
  phantomAccessToken: string;
  /**
   * Raw DPoP proof (no `DPoP ` prefix) for the DpopAuthGuard.
   * Must include `ath = base64url(sha256(phantomAccessToken))` in its claims.
   * Use `buildDpopAuthHeader(proofJwt)` to wrap if you need the `DPoP `
   * prefix; here the wire value is the raw compact JWT.
   */
  dpopProofJwt: string;
};

export async function logout(
  req: LogoutRequest,
): Promise<AegisCallResult<null>> {
  return call<null>("POST", `/api/v1/${req.country}/public/logout`, {
    body: { refresh_token: req.refreshToken },
    extraHeaders: {
      // The public-logout handler calls `extractBearerTokenFromRequest`,
      // so the Authorization scheme MUST be `Bearer`, not `DPoP`.
      Authorization: buildPhantomAuthHeader("Bearer", req.phantomAccessToken),
      DPoP: req.dpopProofJwt,
    },
  });
}

export async function introspect(
  token: string,
  callerService = "aegis-demo-ui",
): Promise<AegisCallResult<IntrospectTokenResponse>> {
  return call<IntrospectTokenResponse>("POST", `/internal/token/introspect`, {
    body: { token },
    extraHeaders: { "X-Caller-Service": callerService },
  });
}

export type GetMeRequest = {
  phantomAccessToken: string;
  /**
   * Raw DPoP proof (no `DPoP ` prefix) for the DpopAuthGuard.
   * Must include `ath = base64url(sha256(phantomAccessToken))` in its claims.
   */
  dpopProofJwt: string;
};

export async function getMe(
  req: GetMeRequest,
): Promise<AegisCallResult<AegisStandardEnvelope<PhantomUserMeResponse>>> {
  return call<AegisStandardEnvelope<PhantomUserMeResponse>>(
    "GET",
    `/api/v1/users/me`,
    {
      extraHeaders: {
        Authorization: buildPhantomAuthHeader("DPoP", req.phantomAccessToken),
        DPoP: req.dpopProofJwt,
      },
    },
  );
}

export { call as rawCall };
