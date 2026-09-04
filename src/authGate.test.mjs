import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createAuthGate,
  createSignedSession,
  isSecureRequest,
  normalizeReturnPath,
  resolveAuthConfig,
  verifySignedSession,
} from '../server/authGate.js';

const credentials = {
  GEV_AUTH_USERNAME: 'personal-owner',
  GEV_AUTH_PASSWORD: 'a-long-test-password',
  GEV_AUTH_SESSION_HOURS: '2',
};

test('auth is optional on an unconfigured local checkout', () => {
  assert.deepEqual(resolveAuthConfig({}), { mode: 'disabled', isReplit: false });
});

test('Replit fails closed if either required Secret is missing', () => {
  const missing = resolveAuthConfig({ REPLIT_DEPLOYMENT: '1' });
  assert.equal(missing.mode, 'misconfigured');
  assert.match(missing.reason, /Both GEV_AUTH_USERNAME and GEV_AUTH_PASSWORD/);
});

test('a LAN-visible local server also fails closed without credentials', () => {
  const config = resolveAuthConfig({ HOST: '0.0.0.0' });
  assert.equal(config.mode, 'misconfigured');
  assert.equal(config.isReplit, false);
});

test('short passwords fail closed', () => {
  const config = resolveAuthConfig({
    GEV_AUTH_USERNAME: 'owner',
    GEV_AUTH_PASSWORD: 'short',
  });
  assert.equal(config.mode, 'misconfigured');
  assert.match(config.reason, /at least 12/);
});

test('signed sessions validate, expire, and break after password rotation', () => {
  const now = 1_800_000_000_000;
  const config = resolveAuthConfig(credentials);
  const session = createSignedSession(config, now);
  assert.equal(verifySignedSession(session, config, now + 1_000), true);
  assert.equal(verifySignedSession(session, config, now + config.sessionMs + 1), false);

  const rotated = resolveAuthConfig({
    ...credentials,
    GEV_AUTH_PASSWORD: 'a-different-long-password',
  });
  assert.equal(verifySignedSession(session, rotated, now + 1_000), false);
});

test('unsafe or auth-loop return paths are replaced with root', () => {
  assert.equal(normalizeReturnPath('https://attacker.example'), '/');
  assert.equal(normalizeReturnPath('//attacker.example'), '/');
  assert.equal(normalizeReturnPath('/auth/logout'), '/');
  assert.equal(normalizeReturnPath('/login?next=/secret'), '/');
  assert.equal(normalizeReturnPath('/?scene=home'), '/?scene=home');
});

test('Replit and forwarded HTTPS requests produce secure cookies', () => {
  const local = resolveAuthConfig(credentials);
  assert.equal(isSecureRequest({ headers: {}, socket: {} }, local), false);
  assert.equal(isSecureRequest({ headers: { 'x-forwarded-proto': 'https' }, socket: {} }, local), true);

  const replit = resolveAuthConfig({ ...credentials, REPLIT_DEPLOYMENT: '1' });
  assert.equal(isSecureRequest({ headers: {}, socket: {} }, replit), true);
});

test('security headers preserve an origin-only referrer for policy-compliant map tiles', () => {
  const headers = new Map();
  const response = {
    setHeader(name, value) {
      headers.set(name, value);
    },
    end() {},
  };
  const gate = createAuthGate({ env: {}, logger: { warn() {}, error() {}, info() {} } });

  gate({ url: '/healthz', method: 'GET', headers: {}, socket: {} }, response, () => {});

  assert.equal(headers.get('Referrer-Policy'), 'strict-origin-when-cross-origin');
  assert.equal(headers.get('X-Frame-Options'), 'DENY');
});
