import { v4 as uuidv4 } from 'uuid';

import { generateDpopKeyPair, type DpopKeyPair } from './dpop';
import type { DemoSessionState, DpopAlg } from './types';

type SessionInternal = DemoSessionState & {
  dpopKeyPair?: DpopKeyPair;
};

let state: SessionInternal | null = null;

const listeners = new Set<() => void>();

function notify(): void {
  for (const l of listeners) l();
}

export function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function getSession(): DemoSessionState | null {
  if (!state) return null;
  // Strip the private key from the public projection.
  const { dpopKeyPair: _dpopKeyPair, ...publicState } = state;
  return publicState;
}

export function getDpopKeyPair(): DpopKeyPair | null {
  return state?.dpopKeyPair ?? null;
}

export async function initSession(country: string, alg: DpopAlg): Promise<void> {
  const dpopKeyPair = await generateDpopKeyPair(alg);
  state = {
    country,
    dpopAlg: alg,
    dpopPublicJwk: { ...dpopKeyPair.publicJwk },
    dpopJkt: dpopKeyPair.jkt,
  };
  notify();
}

export function rotateDpopKeyPair(alg: DpopAlg): Promise<void> {
  if (!state) return Promise.resolve();
  return generateDpopKeyPair(alg).then((kp) => {
    state = {
      ...state!,
      dpopAlg: alg,
      dpopKeyPair: kp,
      dpopPublicJwk: { ...kp.publicJwk },
      dpopJkt: kp.jkt,
      lastJti: undefined,
      jtiIssuedAt: undefined,
    };
    notify();
  });
}

export function setCredentials(username: string, channelId: string): void {
  if (!state) return;
  state = { ...state, username, channelId };
  notify();
}

export function setPhantomTokens(access: string, refresh: string, expiresIn: number): void {
  if (!state) return;
  state = {
    ...state,
    accessToken: access,
    refreshToken: refresh,
    expiresAt: Date.now() + expiresIn * 1000,
  };
  notify();
}

export function clearPhantomTokens(): void {
  if (!state) return;
  state = { ...state, accessToken: undefined, refreshToken: undefined, expiresAt: undefined };
  notify();
}

export function setLastJti(jti: string, iat: number): void {
  if (!state) return;
  state = { ...state, lastJti: jti, jtiIssuedAt: iat };
  notify();
}

export function newAntiReplayJti(): { jti: string; iat: number } {
  const jti = uuidv4();
  const iat = Math.floor(Date.now() / 1000);
  setLastJti(jti, iat);
  return { jti, iat };
}

export function resetSession(): void {
  state = null;
  notify();
}

export function fingerprintFromBrowser(): { fingerprint: string; ip: string; userAgent: string } {
  // The browser cannot know its public IP. We use a fixed string per session so the
  // device_context payload still satisfies the DTO while remaining clearly synthetic.
  const fingerprintSeed = `${navigator.userAgent}-${navigator.language}-${(navigator as Navigator & { hardwareConcurrency?: number }).hardwareConcurrency ?? 'na'}`;
  let hash = 0;
  for (let i = 0; i < fingerprintSeed.length; i++) {
    hash = (hash * 31 + fingerprintSeed.charCodeAt(i)) >>> 0;
  }
  return {
    fingerprint: `sha256-${hash.toString(16).padStart(8, '0')}-demo`,
    ip: '127.0.0.1',
    userAgent: navigator.userAgent.slice(0, 200),
  };
}
