#!/usr/bin/env node
/**
 * Full AEGIS-DEMO coverage: all tabs + security test scenarios.
 * Run: pnpm e2e:full
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
const PASSWORD = process.env.PASSWORD || `Demo!Pass${RUN_ID}`;

const deviceContext = {
  fingerprint: `sha256-e2e-${RUN_ID}`,
  ip: '127.0.0.1',
  userAgent: 'aegis-demo-e2e-full/1.0',
};

const results = [];

function record(name, pass, detail) {
  results.push({ name, pass, detail });
  const icon = pass ? 'PASS' : 'FAIL';
  console.log(`[${icon}] ${name}${detail ? ` — ${detail}` : ''}`);
}

async function http(method, path, { headers = {}, body } = {}) {
  const url = `${BASE}${path}`;
  const res = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, ok: res.ok, data };
}

async function sha256b64url(input) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Buffer.from(digest).toString('base64url');
}

async function generateDpopKeyPair() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  publicJwk.alg = 'ES256';
  const jkt = await calculateJwkThumbprint(publicJwk, 'sha256');
  return { alg: 'ES256', privateKey: kp.privateKey, publicJwk, jkt };
}

async function buildDpopProof({ keyPair, htm, htuPath, phantomAccessToken, tamperHtu }) {
  const htu = tamperHtu ?? `${PUBLIC_ORIGIN}${htuPath}`;
  const payload = { htm, htu, iat: Math.floor(Date.now() / 1000), jti: randomUUID() };
  if (phantomAccessToken) payload.ath = await sha256b64url(phantomAccessToken);
  return new SignJWT(payload)
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: keyPair.publicJwk })
    .sign(keyPair.privateKey);
}

async function getEncryptionKey() {
  const res = await http('GET', '/api/v1/auth/encryption-key');
  if (!res.ok) throw new Error(`encryption-key HTTP ${res.status}`);
  return res.data.data;
}

async function encryptJwe(jwk, plaintext) {
  const key = await importJWK(jwk, jwk.alg);
  return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(plaintext)))
    .setProtectedHeader({ alg: jwk.alg, enc: 'A256GCM' })
    .encrypt(key);
}

async function createUser(encJwk) {
  const secure_payload = await encryptJwe(encJwk, {
    user_identifier: EMAIL,
    clientId: CLIENT_ID,
    userData: { username: USERNAME, email: EMAIL, password: PASSWORD },
    credentials: { user_check: EMAIL },
    anti_replay: { iat: Math.floor(Date.now() / 1000), jti: randomUUID() },
  });
  return http('POST', `/api/v1/${COUNTRY}/public/user`, {
    body: { user_identifier: EMAIL, device_context: deviceContext, secure_payload },
  });
}

async function login(encJwk, keyPair, { tamperHtu } = {}) {
  const secure_payload = await encryptJwe(encJwk, {
    user_identifier: USERNAME,
    credentials: { clientId: CLIENT_ID, pass: PASSWORD, user_check: USERNAME },
    anti_replay: { iat: Math.floor(Date.now() / 1000), jti: randomUUID() },
  });
  const proofJwt = await buildDpopProof({
    keyPair,
    htm: 'POST',
    htuPath: `/api/v1/${COUNTRY}/public/login`,
    tamperHtu,
  });
  return http('POST', `/api/v1/${COUNTRY}/public/login`, {
    headers: { DPoP: `DPoP ${proofJwt}` },
    body: { user_identifier: USERNAME, device_context: deviceContext, secure_payload },
  });
}

async function introspect(token) {
  return http('POST', '/api/v1/internal/token/introspect', {
    headers: { 'X-Internal-API-Key': INTERNAL_API_KEY, 'X-Caller-Service': 'aegis-demo-e2e-full' },
    body: { token },
  });
}

async function getMe(accessToken, keyPair) {
  const proofJwt = await buildDpopProof({
    keyPair, htm: 'GET', htuPath: '/api/v1/users/me', phantomAccessToken: accessToken,
  });
  return http('GET', '/api/v1/users/me', {
    headers: { Authorization: `DPoP ${accessToken}`, DPoP: proofJwt },
  });
}

async function refresh(accessToken, refreshToken, keyPair) {
  const proofJwt = await buildDpopProof({
    keyPair, htm: 'POST', htuPath: '/api/v1/auth/refresh-token', phantomAccessToken: accessToken,
  });
  return http('POST', '/api/v1/auth/refresh-token', {
    headers: { Authorization: `DPoP ${accessToken}`, DPoP: proofJwt },
    body: { refresh_token: refreshToken, client_id: CLIENT_ID },
  });
}

async function logout(accessToken, refreshToken, keyPair) {
  const encJwk = await getEncryptionKey();
  const secure_payload = await encryptJwe(encJwk, {
    credentials: { clientId: CLIENT_ID, pass: refreshToken, user_check: USERNAME },
    anti_replay: { iat: Math.floor(Date.now() / 1000), jti: randomUUID() },
  });
  const proofJwt = await buildDpopProof({
    keyPair, htm: 'POST', htuPath: `/api/v1/${COUNTRY}/public/logout`, phantomAccessToken: accessToken,
  });
  return http('POST', `/api/v1/${COUNTRY}/public/logout`, {
    headers: { Authorization: `Bearer ${accessToken}`, DPoP: proofJwt },
    body: { user_identifier: USERNAME, device_context: deviceContext, secure_payload },
  });
}

async function main() {
  console.log('=== AEGIS-DEMO Full E2E ===');
  console.log({ BASE, CLIENT_ID, USERNAME, EMAIL });

  if (!INTERNAL_API_KEY) {
    record('Config: internal API key', false, 'VITE_AEGIS_INTERNAL_API_KEY missing');
    process.exit(1);
  }

  const encJwk = await getEncryptionKey();
  record('Tab 0: encryption-key', true, `alg=${encJwk.alg}`);

  // Tab 1: Create User
  const createRes = await createUser(encJwk);
  const createOk = createRes.status === 201 || createRes.status === 409;
  record('Tab 1: Create User', createOk, `HTTP ${createRes.status}`);
  if (!createOk) process.exit(1);

  const keyPair = await generateDpopKeyPair();

  // Tab 2: Login
  const loginRes = await login(encJwk, keyPair);
  record('Tab 2: Login', loginRes.ok, `HTTP ${loginRes.status} jkt=${keyPair.jkt}`);
  if (!loginRes.ok) process.exit(1);

  let { access_token, refresh_token } = loginRes.data;

  // Tab 4: Introspect
  const introRes = await introspect(access_token);
  const introOk = introRes.ok && introRes.data.active === true;
  const jktMatch = introRes.data?.dpop_jkt === keyPair.jkt;
  record('Tab 4: Introspect', introOk, `HTTP ${introRes.status} active=${introRes.data?.active}`);
  record('Phantom↔DPoP link', jktMatch, `introspect jkt=${introRes.data?.dpop_jkt}`);

  // Tab 5: /users/me
  const meRes = await getMe(access_token, keyPair);
  const meOk = meRes.ok && meRes.data?.data?.channelId === CLIENT_ID;
  record('Tab 5: /users/me', meOk, `HTTP ${meRes.status}`);

  // Tab 6: Refresh
  const refreshRes = await refresh(access_token, refresh_token, keyPair);
  const refreshOk = refreshRes.ok && refreshRes.data?.access_token && refreshRes.data?.refresh_token;
  record('Tab 6: Refresh', refreshOk, `HTTP ${refreshRes.status}`);
  if (refreshOk) {
    access_token = refreshRes.data.access_token;
    refresh_token = refreshRes.data.refresh_token;
  }

  // Security Test scenarios
  const tamperedLogin = await login(encJwk, keyPair, {
    tamperHtu: `${PUBLIC_ORIGIN}/api/v1/${COUNTRY}/public/logout`,
  });
  record('Security: Login DPoP htu alterado', !tamperedLogin.ok, `HTTP ${tamperedLogin.status}`);

  const altPair = await generateDpopKeyPair();
  const meWrongJkt = await getMe(access_token, altPair);
  record('Security: /users/me DPoP diferente', !meWrongJkt.ok, `HTTP ${meWrongJkt.status}`);

  const meBadPhantom = await getMe('00000000-0000-4000-8000-000000000000', keyPair);
  record('Security: /users/me Phantom inválido', !meBadPhantom.ok, `HTTP ${meBadPhantom.status}`);

  const introInvalid = await introspect('00000000-0000-4000-8000-000000000000');
  record('Security: Introspect token inválido', introInvalid.ok && introInvalid.data.active === false, `HTTP ${introInvalid.status}`);

  const logoutWrongDpop = await logout(access_token, refresh_token, altPair);
  record('Security: Logout DPoP diferente', logoutWrongDpop.status === 204, `HTTP ${logoutWrongDpop.status} (aegis always 204)`);
  const meAfterBadLogout = await getMe(access_token, keyPair);
  record('Security: sesión activa tras logout DPoP malo', meAfterBadLogout.ok, `HTTP ${meAfterBadLogout.status}`);

  // Tab 3: Logout (valid)
  const logoutRes = await logout(access_token, refresh_token, keyPair);
  record('Tab 3: Logout', logoutRes.status === 204, `HTTP ${logoutRes.status}`);

  const introAfter = await introspect(access_token);
  const inactiveAfterLogout = introAfter.data?.active === false;
  record('Tab 3: post-logout introspect inactive', inactiveAfterLogout,
    inactiveAfterLogout ? 'active:false' : 'active:true (known aegis-core gap: Redis session not deleted)');

  console.log('\n=== Summary ===');
  const passed = results.filter((r) => r.pass).length;
  const failed = results.filter((r) => !r.pass);
  console.log(`${passed}/${results.length} checks passed`);
  if (failed.length) {
    console.log('Failed:');
    for (const f of failed) console.log(`  - ${f.name}: ${f.detail ?? ''}`);
  }

  const critical = failed.filter((f) => !f.name.includes('post-logout'));
  process.exit(critical.length ? 1 : 0);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
