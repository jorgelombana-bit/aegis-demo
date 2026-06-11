export type DpopAlg = 'ES256' | 'RS256' | 'PS256';

export type AegisStandardEnvelope<T> = {
  code: number;
  message: string;
  data: T;
};

export type AegisErrorEnvelope = {
  error?: string;
  error_description?: string;
  message?: string | string[];
  code?: number;
  statusCode?: number;
};

export type EncryptionKeyJwk = {
  kty: string;
  alg: string;
  use: 'enc';
  kid: string;
  n?: string;
  e?: string;
  crv?: string;
  x?: string;
  y?: string;
};

export type PublicHumanLoginResponse = {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: 'DPoP';
};

export type PublicHumanRegisterResponse = {
  message: string;
};

export type IntrospectTokenResponse = {
  active: boolean;
  sub?: string;
  country?: string;
  client_id?: string;
  roles?: string[];
  dpop_jkt?: string;
  iat?: number;
  exp?: number;
};

export type PhantomUserMeResponse = {
  userId: string;
  sessionId: string;
  username: string;
  email?: string;
  country: string;
  roles: string[];
  clientId: string;
  channelId: string;
};

export type DeviceContext = {
  fingerprint: string;
  ip: string;
  userAgent: string;
};

export type DemoSessionState = {
  country: string;
  dpopAlg: DpopAlg;
  dpopPublicJwk: Record<string, unknown>;
  dpopJkt: string;
  username?: string;
  channelId?: string;
  accessToken?: string;
  refreshToken?: string;
  expiresAt?: number;
  jtiIssuedAt?: number;
  lastJti?: string;
};
