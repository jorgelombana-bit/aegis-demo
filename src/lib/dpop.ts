import { calculateJwkThumbprint, importJWK, SignJWT, type JWK } from 'jose';
import { v4 as uuidv4 } from 'uuid';

import type { DpopAlg } from './types';

export type DpopKeyPair = {
  alg: DpopAlg;
  privateKey: CryptoKey;
  publicJwk: JWK;
  jkt: string;
};

async function generateKeyPair(alg: DpopAlg): Promise<{ privateKey: CryptoKey; publicJwk: JWK }> {
  switch (alg) {
    case 'ES256': {
      const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
      );
      const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
      return { privateKey: keyPair.privateKey, publicJwk: { ...publicJwk, alg: 'ES256' } };
    }
    case 'RS256': {
      const keyPair = await crypto.subtle.generateKey(
        { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true,
        ['sign', 'verify']
      );
      const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
      return { privateKey: keyPair.privateKey, publicJwk: { ...publicJwk, alg: 'RS256' } };
    }
    case 'PS256': {
      const keyPair = await crypto.subtle.generateKey(
        { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true,
        ['sign', 'verify']
      );
      const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
      return { privateKey: keyPair.privateKey, publicJwk: { ...publicJwk, alg: 'PS256' } };
    }
  }
}

export async function generateDpopKeyPair(alg: DpopAlg): Promise<DpopKeyPair> {
  const { privateKey, publicJwk } = await generateKeyPair(alg);
  // jose expects a complete JWK; thumbprint is the base64url(sha256(canonical jwk)).
  const jkt = await calculateJwkThumbprint(publicJwk as JWK, 'sha256');
  return { alg, privateKey, publicJwk, jkt };
}

export async function loadKeyPairFromJwk(
  alg: DpopAlg,
  publicJwk: JWK,
  privateKey: CryptoKey
): Promise<DpopKeyPair> {
  const jkt = await calculateJwkThumbprint(publicJwk, 'sha256');
  return { alg, privateKey, publicJwk, jkt };
}

async function base64UrlSha256(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  let binary = '';
  const view = new Uint8Array(digest);
  for (let i = 0; i < view.length; i++) {
    binary += String.fromCharCode(view[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export type BuildDpopProofInput = {
  keyPair: DpopKeyPair;
  htm: 'GET' | 'POST' | 'PUT' | 'DELETE';
  htu: string;
  // ath is required for phantom-token-protected endpoints (logout, /users/me). Omit for login.
  phantomAccessToken?: string;
  jti?: string;
  iat?: number;
  // Allow the Security Test view to mutate the proof without touching signing logic.
  tamper?: (unsigned: { header: Record<string, unknown>; payload: Record<string, unknown> }) => void;
};

export async function buildDpopProof(input: BuildDpopProofInput): Promise<string> {
  const iat = input.iat ?? Math.floor(Date.now() / 1000);
  const jti = input.jti ?? uuidv4();

  const header: Record<string, unknown> = {
    typ: 'dpop+jwt',
    alg: input.keyPair.alg,
    jwk: input.keyPair.publicJwk,
  };

  const payload: Record<string, unknown> = {
    htm: input.htm,
    htu: input.htu,
    iat,
    jti,
  };

  if (input.phantomAccessToken) {
    payload.ath = await base64UrlSha256(input.phantomAccessToken);
  }

  if (input.tamper) {
    input.tamper({ header, payload });
  }

  // We use jose.SignJWT so the library builds the canonical JWS string.
  // Re-instantiate a fresh SignJWT (jose's API is immutable).
  const builder = new SignJWT(payload as Record<string, unknown> & { [k: string]: unknown });
  builder.setProtectedHeader({
    ...(header as Record<string, unknown>),
    typ: 'dpop+jwt',
    alg: input.keyPair.alg,
    jwk: input.keyPair.publicJwk,
  } as Parameters<typeof builder.setProtectedHeader>[0]);

  // Re-key key by alg: importJWK gives us a KeyLike usable for signing.
  const signingKey = await importJWK(input.keyPair.publicJwk as JWK, input.keyPair.alg);
  return await builder.sign(signingKey);
}

export function htuForAegis(
  path: string,
  publicOrigin = (import.meta.env.VITE_AEGIS_PUBLIC_ORIGIN as string | undefined) ||
    'https://aegis-dev.preprodcxr.co'
): string {
  // path must start with /api/v1 or /internal
  return `${publicOrigin.replace(/\/+$/, '')}${path}`;
}
