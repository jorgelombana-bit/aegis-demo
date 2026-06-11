import { CompactEncrypt, importJWK, type JWK } from 'jose';

import { getEncryptionKey } from './api';
import type { EncryptionKeyJwk } from './types';

const cache = new Map<string, { key: CryptoKey; jwk: EncryptionKeyJwk; alg: string; enc: string }>();

async function loadEncryptionKey(country: string): Promise<{
  key: CryptoKey;
  jwk: EncryptionKeyJwk;
  alg: string;
  enc: string;
}> {
  const cached = cache.get(country);
  if (cached) return cached;

  const jwk = await getEncryptionKey();
  const alg = jwk.alg;
  // aegis-core only supports A256GCM (validated in JweDecryptService).
  const enc = 'A256GCM';

  const key = (await importJWK(jwk as JWK, alg)) as CryptoKey;

  const entry = { key, jwk, alg, enc };
  cache.set(country, entry);
  return entry;
}

export function clearEncryptionKeyCache(): void {
  cache.clear();
}

export async function encryptJwe(
  country: string,
  plaintext: Record<string, unknown>
): Promise<string> {
  const { key, alg, enc } = await loadEncryptionKey(country);
  const encoder = new TextEncoder();
  const jwe = await new CompactEncrypt(encoder.encode(JSON.stringify(plaintext)))
    .setProtectedHeader({ alg, enc })
    .encrypt(key);
  return jwe;
}
