#!/usr/bin/env node
/**
 * End-to-end Aegis security flow tester (curl-equivalent).
 *
 * Usage:
 *   node scripts/e2e-flow.mjs
 *   AEGIS_BASE_URL=https://aegis-dev.preprodcxr.co \
 *   INTERNAL_API_KEY=<key> \
 *   node scripts/e2e-flow.mjs
 *
 * Optional env:
 *   COUNTRY=co
 *   CLIENT_ID=a1b2c3d4-e5f6-4789-a012-000000000001
 *   USERNAME / PASSWORD / EMAIL — auto-generated if omitted
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CompactEncrypt, importJWK, SignJWT, calculateJwkThumbprint } from 'jose';
import { randomUUID } from 'node:crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const envPath = resolve(__dirname, '../.env');
if (existsSync(envPath)) {
  for (const line of readFileSync(envPath, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const val = trimmed.slice(eq + 1).trim();
    if (process.env[key] === undefined) process.env[key] = val;
  }
}

const BASE = (process.env.AEGIS_BASE_URL || 'https://aegis-dev.preprodcxr.co').replace(/\/+$/, '');
const PUBLIC_ORIGIN = (process.env.AEGIS_PUBLIC_ORIGIN || BASE).replace(/\/+$/, '');
const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY || process.env.VITE_AEGIS_INTERNAL_API_KEY || '';
const COUNTRY = process.env.COUNTRY || 'co';
const CLIENT_ID = process.env.CLIENT_ID || 'c81f6463-45e8-4df5-a953-aba7d8ed6514';
const RUN_ID = Date.now().toString(36);

const USERNAME = process.env.USERNAME || `demo.${RUN_ID}`;
const EMAIL = process.env.EMAIL || `${USERNAME}@demo.test`;
// CHANNEL-MAY-29 policy: min 12, uppercase, symbol, must not contain username.
const PASSWORD = process.env.PASSWORD || `Demo!Pass${RUN_ID}`;

const deviceContext = {
  fingerprint: `sha256-e2e-${RUN_ID}`,
  ip: '127.0.0.1',
  userAgent: 'aegis-demo-e2e/1.0',
};

function log(step, msg, extra) {
  const prefix = `[${step}]`;
  if (extra !== undefined) console.log(prefix, msg, typeof extra === 'string' ? extra : JSON.stringify(extra, null, 2));
  else console.log(prefix, msg);
}

async function http(method, path, { headers = {}, body } = {}) {
  const url = `${BASE}${path}`;
  const res = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data;
  const text = await res.text();
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  return { status: res.status, ok: res.ok, data, url };
}

async function sha256b64url(input) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Buffer.from(digest).toString('base64url');
}

async function generateDpopKeyPair(alg = 'ES256') {
  let privateKey;
  let publicJwk;
  if (alg === 'ES256') {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    privateKey = kp.privateKey;
    publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    publicJwk.alg = 'ES256';
  } else {
    throw new Error(`Unsupported alg in e2e script: ${alg}`);
  }
  const jkt = await calculateJwkThumbprint(publicJwk, 'sha256');
  return { alg, privateKey, publicJwk, jkt };
}

async function buildDpopProof({ keyPair, htm, htuPath, phantomAccessToken, jti = randomUUID(), iat = Math.floor(Date.now() / 1000) }) {
  const htu = `${PUBLIC_ORIGIN}${htuPath}`;
  const payload = { htm, htu, iat, jti };
  if (phantomAccessToken) payload.ath = await sha256b64url(phantomAccessToken);
  return new SignJWT(payload)
    .setProtectedHeader({ typ: 'dpop+jwt', alg: keyPair.alg, jwk: keyPair.publicJwk })
    .sign(keyPair.privateKey);
}

async function getEncryptionKey() {
  const res = await http('GET', '/api/v1/auth/encryption-key');
  if (!res.ok) throw new Error(`encryption-key HTTP ${res.status}: ${JSON.stringify(res.data)}`);
  return res.data.data;
}

async function encryptJwe(jwk, plaintext) {
  const key = await importJWK(jwk, jwk.alg);
  return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(plaintext)))
    .setProtectedHeader({ alg: jwk.alg, enc: 'A256GCM' })
    .encrypt(key);
}

async function stepCreateUser(encJwk) {
  const securePlaintext = {
    user_identifier: EMAIL,
    clientId: CLIENT_ID,
    userData: { username: USERNAME, email: EMAIL, password: PASSWORD },
    credentials: { user_check: EMAIL },
    anti_replay: { iat: Math.floor(Date.now() / 1000), jti: randomUUID() },
  };
  const secure_payload = await encryptJwe(encJwk, securePlaintext);
  const res = await http('POST', `/api/v1/${COUNTRY}/public/user`, {
    body: { user_identifier: EMAIL, device_context: deviceContext, secure_payload },
  });
  log('CREATE', `HTTP ${res.status}`, res.data);
  return res;
}

async function stepLogin(encJwk, keyPair) {
  const securePlaintext = {
    user_identifier: USERNAME,
    credentials: { clientId: CLIENT_ID, pass: PASSWORD, user_check: USERNAME },
    anti_replay: { iat: Math.floor(Date.now() / 1000), jti: randomUUID() },
  };
  const secure_payload = await encryptJwe(encJwk, securePlaintext);
  const proofJwt = await buildDpopProof({ keyPair, htm: 'POST', htuPath: `/api/v1/${COUNTRY}/public/login` });
  const res = await http('POST', `/api/v1/${COUNTRY}/public/login`, {
    headers: { DPoP: `DPoP ${proofJwt}` },
    body: { user_identifier: USERNAME, device_context: deviceContext, secure_payload },
  });
  log('LOGIN', `HTTP ${res.status} jkt=${keyPair.jkt}`, res.data);
  return res;
}

async function stepIntrospect(token, label = 'INTROSPECT') {
  if (!INTERNAL_API_KEY) {
    log(label, 'SKIP — set INTERNAL_API_KEY or VITE_AEGIS_INTERNAL_API_KEY');
    return null;
  }
  const res = await http('POST', '/api/v1/internal/token/introspect', {
    headers: {
      'X-Internal-API-Key': INTERNAL_API_KEY,
      'X-Caller-Service': 'aegis-demo-e2e',
    },
    body: { token },
  });
  log(label, `HTTP ${res.status}`, res.data);
  return res;
}

async function stepGetMe(accessToken, keyPair) {
  const proofJwt = await buildDpopProof({
    keyPair,
    htm: 'GET',
    htuPath: '/api/v1/users/me',
    phantomAccessToken: accessToken,
  });
  const res = await http('GET', '/api/v1/users/me', {
    headers: {
      Authorization: `DPoP ${accessToken}`,
      DPoP: proofJwt,
    },
  });
  log('GET /users/me', `HTTP ${res.status}`, res.data);
  return res;
}

async function stepLogout(accessToken, refreshToken, keyPair) {
  const securePlaintext = {
    credentials: { clientId: CLIENT_ID, pass: refreshToken, user_check: USERNAME },
    anti_replay: { iat: Math.floor(Date.now() / 1000), jti: randomUUID() },
  };
  const encJwk = await getEncryptionKey();
  const secure_payload = await encryptJwe(encJwk, securePlaintext);
  const proofJwt = await buildDpopProof({
    keyPair,
    htm: 'POST',
    htuPath: `/api/v1/${COUNTRY}/public/logout`,
    phantomAccessToken: accessToken,
  });
  const res = await http('POST', `/api/v1/${COUNTRY}/public/logout`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      DPoP: proofJwt,
    },
    body: { user_identifier: USERNAME, device_context: deviceContext, secure_payload },
  });
  log('LOGOUT', `HTTP ${res.status}`, res.data ?? '(empty)');
  return res;
}

async function main() {
  console.log('=== Aegis E2E flow ===');
  console.log({ BASE, PUBLIC_ORIGIN, COUNTRY, CLIENT_ID, USERNAME, EMAIL });

  const encJwk = await getEncryptionKey();
  log('ENC-KEY', `alg=${encJwk.alg} kid=${encJwk.kid}`);

  const createRes = await stepCreateUser(encJwk);
  if (createRes.status !== 201 && createRes.status !== 409) {
    console.error('Create user failed — aborting');
    process.exit(1);
  }

  const keyPair = await generateDpopKeyPair('ES256');
  const loginRes = await stepLogin(encJwk, keyPair);
  if (!loginRes.ok) {
    console.error('Login failed — aborting');
    process.exit(1);
  }

  const { access_token, refresh_token } = loginRes.data;

  const intro = await stepIntrospect(access_token);
  if (intro?.ok && intro.data.active) {
    const match = intro.data.dpop_jkt === keyPair.jkt;
    log('PHANTOM↔DPoP', match ? 'OK — introspect dpop_jkt matches login jkt' : `MISMATCH introspect=${intro.data.dpop_jkt} login=${keyPair.jkt}`);
  }

  const meRes = await stepGetMe(access_token, keyPair);
  if (!meRes.ok) {
    console.error('/users/me with valid token+DPoP failed');
    process.exit(1);
  }

  // Security case: wrong DPoP jkt
  const altPair = await generateDpopKeyPair('ES256');
  const badMe = await stepGetMe(access_token, altPair);
  log('CASE wrong-jkt', badMe.ok ? 'UNEXPECTED 2xx' : `expected reject HTTP ${badMe.status}`);

  const badIntro = await stepIntrospect(randomUUID(), 'INTROSPECT invalid token');
  if (badIntro?.ok && badIntro.data.active === false) {
    log('CASE invalid-token', 'OK — active:false');
  }

  await stepLogout(access_token, refresh_token, keyPair);

  const afterLogout = await stepIntrospect(access_token, 'INTROSPECT after logout');
  if (afterLogout?.ok && afterLogout.data.active === false) {
    log('POST-LOGOUT', 'OK — token inactive');
  } else if (afterLogout?.ok && afterLogout.data.active === true) {
    log('POST-LOGOUT', 'WARN — token still active after logout HTTP 204');
    log('POST-LOGOUT', 'aegis-core public logout revokes Keycloak refresh but may not delete phantom Redis sessions yet');
    process.exitCode = 2;
  }

  console.log('\n=== All primary flows completed ===');
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
