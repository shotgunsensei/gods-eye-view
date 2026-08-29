import {
  createHash,
  createHmac,
  timingSafeEqual,
} from 'node:crypto';

const COOKIE_NAME = 'gev_session';
const DEFAULT_SESSION_HOURS = 12;
const MAX_SESSION_HOURS = 168;
const MAX_FORM_BYTES = 8 * 1024;
const MAX_ATTEMPTS = 5;
const ATTEMPT_WINDOW_MS = 15 * 60 * 1000;

function sha256(value) {
  return createHash('sha256').update(String(value), 'utf8').digest();
}

function constantTimeTextEqual(actual, expected) {
  return timingSafeEqual(sha256(actual), sha256(expected));
}

function clampSessionHours(value) {
  const parsed = Number.parseInt(String(value || ''), 10);
  if (!Number.isFinite(parsed)) return DEFAULT_SESSION_HOURS;
  return Math.min(MAX_SESSION_HOURS, Math.max(1, parsed));
}

/**
 * Resolve password-wall behavior from server-only environment variables.
 * Replit runs fail closed when the two required Secrets are absent.
 */
export function resolveAuthConfig(env = process.env) {
  const username = String(env.GEV_AUTH_USERNAME || '').trim();
  const password = String(env.GEV_AUTH_PASSWORD || '');
  const isReplit = env.REPLIT_DEPLOYMENT === '1'
    || Boolean(env.REPLIT_DEV_DOMAIN)
    || Boolean(env.REPL_ID);
  const configuredHost = String(env.HOST || '').trim().toLowerCase();
  const isNetworkExposed = isReplit
    || configuredHost === '0.0.0.0'
    || configuredHost === '::';

  if (!username && !password && !isNetworkExposed) {
    return { mode: 'disabled', isReplit: false };
  }

  if (!username || !password) {
    return {
      mode: 'misconfigured',
      isReplit,
      reason: 'Both GEV_AUTH_USERNAME and GEV_AUTH_PASSWORD must be set.',
    };
  }

  if (password.length < 12) {
    return {
      mode: 'misconfigured',
      isReplit,
      reason: 'GEV_AUTH_PASSWORD must contain at least 12 characters.',
    };
  }

  return {
    mode: 'enabled',
    isReplit,
    username,
    password,
    sessionMs: clampSessionHours(env.GEV_AUTH_SESSION_HOURS) * 60 * 60 * 1000,
    signingKey: sha256(`gev-session-v1\0${username}\0${password}`),
  };
}

function encodeBase64Url(value) {
  return Buffer.from(value, 'utf8').toString('base64url');
}

function decodeBase64Url(value) {
  return Buffer.from(value, 'base64url').toString('utf8');
}

export function createSignedSession(config, now = Date.now()) {
  const payload = encodeBase64Url(JSON.stringify({
    v: 1,
    u: config.username,
    exp: now + config.sessionMs,
  }));
  const signature = createHmac('sha256', config.signingKey)
    .update(payload)
    .digest('base64url');
  return `${payload}.${signature}`;
}

export function verifySignedSession(value, config, now = Date.now()) {
  if (!value || typeof value !== 'string') return false;
  const parts = value.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return false;

  const [payload, suppliedSignature] = parts;
  const expectedSignature = createHmac('sha256', config.signingKey)
    .update(payload)
    .digest('base64url');
  if (!constantTimeTextEqual(suppliedSignature, expectedSignature)) return false;

  try {
    const parsed = JSON.parse(decodeBase64Url(payload));
    return parsed.v === 1
      && parsed.u === config.username
      && Number.isFinite(parsed.exp)
      && parsed.exp > now;
  } catch {
    return false;
  }
}

function parseCookies(header = '') {
  const cookies = new Map();
  for (const segment of String(header).split(';')) {
    const separator = segment.indexOf('=');
    if (separator < 1) continue;
    const name = segment.slice(0, separator).trim();
    const value = segment.slice(separator + 1).trim();
    if (name) cookies.set(name, value);
  }
  return cookies;
}

export function normalizeReturnPath(value) {
  const candidate = String(value || '').trim();
  if (!candidate.startsWith('/') || candidate.startsWith('//')) return '/';
  if (/^\/(?:login|auth(?:\/|$)|healthz(?:\?|$))/i.test(candidate)) return '/';
  return candidate;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function requestPath(req) {
  try {
    return new URL(req.url || '/', 'http://localhost').pathname;
  } catch {
    return '/';
  }
}

function requestTarget(req) {
  try {
    const url = new URL(req.url || '/', 'http://localhost');
    return normalizeReturnPath(`${url.pathname}${url.search}`);
  } catch {
    return '/';
  }
}

function loginReturnTarget(req) {
  try {
    const url = new URL(req.url || '/', 'http://localhost');
    return normalizeReturnPath(url.searchParams.get('next'));
  } catch {
    return '/';
  }
}

function requestHasSameOrigin(req) {
  const origin = String(req.headers?.origin || '').trim();
  if (!origin) return true;
  const host = String(req.headers?.host || '').trim().toLowerCase();
  if (!host) return false;
  try {
    return new URL(origin).host.toLowerCase() === host;
  } catch {
    return false;
  }
}

export function isSecureRequest(req, config) {
  const forwardedProto = String(req.headers?.['x-forwarded-proto'] || '')
    .split(',')[0]
    .trim()
    .toLowerCase();
  return config.isReplit || forwardedProto === 'https' || Boolean(req.socket?.encrypted);
}

function cookieAttributes(req, config, maxAgeSeconds) {
  const secure = isSecureRequest(req, config) ? '; Secure' : '';
  return `Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSeconds}${secure}`;
}

function sessionCookie(req, config, now) {
  const maxAgeSeconds = Math.floor(config.sessionMs / 1000);
  return `${COOKIE_NAME}=${createSignedSession(config, now)}; ${cookieAttributes(req, config, maxAgeSeconds)}`;
}

function expiredSessionCookie(req, config) {
  return `${COOKIE_NAME}=; ${cookieAttributes(req, config, 0)}`;
}

function applyBaseHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
}

function send(res, statusCode, contentType, body, extraHeaders = {}) {
  const payload = Buffer.from(body, 'utf8');
  res.statusCode = statusCode;
  res.setHeader('Content-Type', contentType);
  res.setHeader('Content-Length', payload.length);
  for (const [name, value] of Object.entries(extraHeaders)) res.setHeader(name, value);
  res.end(payload);
}

function sendJson(res, statusCode, value) {
  send(
    res,
    statusCode,
    'application/json; charset=utf-8',
    JSON.stringify(value),
    { 'Cache-Control': 'private, no-store' },
  );
}

function redirect(res, location, statusCode = 303) {
  res.statusCode = statusCode;
  res.setHeader('Location', location);
  res.setHeader('Cache-Control', 'private, no-store');
  res.end();
}

function loginPage({ next = '/', message = '', status = 200 } = {}) {
  const safeNext = escapeHtml(normalizeReturnPath(next));
  const messageMarkup = message
    ? `<p class="message" role="alert">${escapeHtml(message)}</p>`
    : '<p class="message hint">Private personal console</p>';
  return {
    status,
    html: `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="theme-color" content="#050a0f">
  <title>Sign in · God's Eye View</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
    * { box-sizing: border-box; }
    body { min-height: 100svh; margin: 0; display: grid; place-items: center; padding: 24px; color: #e9fcff; background: radial-gradient(circle at 50% 18%, #123341 0, #071117 36%, #030608 74%); }
    main { width: min(100%, 410px); padding: 34px; border: 1px solid rgba(0,246,255,.28); border-radius: 18px; background: rgba(5,14,19,.9); box-shadow: 0 26px 80px rgba(0,0,0,.55), 0 0 48px rgba(0,246,255,.08); }
    .mark { width: 68px; height: 46px; margin: 0 auto 22px; display: grid; place-items: center; color: #00f6ff; border: 3px solid currentColor; border-radius: 70% 18%; transform: rotate(45deg); box-shadow: 0 0 20px rgba(0,246,255,.25); }
    .mark span { width: 23px; height: 23px; border: 3px solid currentColor; border-radius: 50%; transform: rotate(-45deg); }
    h1 { margin: 0; text-align: center; font: 600 21px/1.2 ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: .16em; }
    .accent { color: #00f6ff; font-weight: 400; }
    .message { min-height: 20px; margin: 13px 0 22px; color: #ff9aa6; text-align: center; font-size: 14px; }
    .message.hint { color: #8aaab4; }
    label { display: grid; gap: 7px; margin: 14px 0; color: #9fc2cb; font-size: 12px; letter-spacing: .08em; text-transform: uppercase; }
    input { width: 100%; min-height: 48px; padding: 11px 13px; color: #effdff; background: #071016; border: 1px solid #29434c; border-radius: 9px; font: 500 16px/1.2 inherit; outline: none; }
    input:focus { border-color: #00f6ff; box-shadow: 0 0 0 3px rgba(0,246,255,.11); }
    button { width: 100%; min-height: 48px; margin-top: 10px; color: #001014; background: #00f6ff; border: 0; border-radius: 9px; font-weight: 800; letter-spacing: .09em; cursor: pointer; }
    button:hover { filter: brightness(1.08); }
    small { display: block; margin-top: 18px; color: #6e8a92; text-align: center; line-height: 1.45; }
  </style>
</head>
<body>
  <main>
    <div class="mark" aria-hidden="true"><span></span></div>
    <h1>GOD'S EYE <span class="accent">VIEW</span></h1>
    ${messageMarkup}
    <form method="post" action="/auth/login">
      <input type="hidden" name="next" value="${safeNext}">
      <label>Account name<input name="username" type="text" autocomplete="username" autocapitalize="none" required autofocus></label>
      <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
      <button type="submit">UNLOCK CONSOLE</button>
    </form>
    <small>This private session expires automatically. Your credentials remain on the server.</small>
  </main>
</body>
</html>`,
  };
}

function setupPage(reason) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Setup required</title>
<style>:root{color-scheme:dark;font-family:system-ui,sans-serif}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:#050a0f;color:#eafcff}main{max-width:600px;padding:32px;border:1px solid #1c6c78;border-radius:14px;background:#071319}h1{color:#00f6ff}code{color:#7ff9ff}li{margin:.7em 0}</style></head>
<body><main><h1>Private sign-in needs setup</h1><p>${escapeHtml(reason)}</p><ol><li>Open Replit <strong>Secrets</strong>.</li><li>Add <code>GEV_AUTH_USERNAME</code>.</li><li>Add <code>GEV_AUTH_PASSWORD</code> with at least 12 characters.</li><li>Restart the app.</li></ol><p>The application is locked until both Secrets are valid.</p></main></body></html>`;
}

function authPageHeaders(res) {
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  );
}

function readForm(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_FORM_BYTES) {
        reject(new Error('FORM_TOO_LARGE'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        resolve(new URLSearchParams(Buffer.concat(chunks).toString('utf8')));
      } catch (error) {
        reject(error);
      }
    });
    req.on('error', reject);
  });
}

function clientAddress(req) {
  const forwarded = String(req.headers?.['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded || req.socket?.remoteAddress || 'unknown';
}

function acceptsHtml(req) {
  return String(req.headers?.accept || '').includes('text/html');
}

/** Create a Connect-compatible middleware protecting every Vite route and proxy. */
export function createAuthGate({ env = process.env, now = () => Date.now(), logger = console } = {}) {
  const config = resolveAuthConfig(env);
  const attempts = new Map();

  if (config.mode === 'disabled') {
    logger.warn('[auth] Password protection is disabled locally; set GEV_AUTH_USERNAME and GEV_AUTH_PASSWORD to enable it.');
  } else if (config.mode === 'misconfigured') {
    logger.error(`[auth] Locked: ${config.reason}`);
  } else {
    logger.info('[auth] Password protection enabled.');
  }

  function isAuthenticated(req) {
    if (config.mode !== 'enabled') return false;
    const value = parseCookies(req.headers?.cookie).get(COOKIE_NAME);
    return verifySignedSession(value, config, now());
  }

  function recentAttemptCount(key) {
    const cutoff = now() - ATTEMPT_WINDOW_MS;
    const recent = (attempts.get(key) || []).filter((timestamp) => timestamp > cutoff);
    if (recent.length) attempts.set(key, recent);
    else attempts.delete(key);
    return recent.length;
  }

  function recordFailure(key) {
    const recent = attempts.get(key) || [];
    recent.push(now());
    attempts.set(key, recent);
  }

  return function authGate(req, res, next) {
    applyBaseHeaders(res);
    const path = requestPath(req);

    if (path === '/healthz') {
      return sendJson(res, 200, { ok: true });
    }

    if (path === '/auth/status') {
      return sendJson(res, 200, { enabled: config.mode === 'enabled' });
    }

    if (config.mode === 'disabled') return next();

    if (config.mode === 'misconfigured') {
      authPageHeaders(res);
      return send(res, 503, 'text/html; charset=utf-8', setupPage(config.reason));
    }

    if (path === '/auth/logout' && req.method === 'POST') {
      if (!requestHasSameOrigin(req)) {
        return sendJson(res, 403, { error: 'Invalid request origin.' });
      }
      res.setHeader('Set-Cookie', expiredSessionCookie(req, config));
      return redirect(res, '/login');
    }

    if (path === '/auth/login' && req.method === 'POST') {
      if (!requestHasSameOrigin(req)) {
        return sendJson(res, 403, { error: 'Invalid request origin.' });
      }
      const address = clientAddress(req);
      if (recentAttemptCount(address) >= MAX_ATTEMPTS) {
        authPageHeaders(res);
        const page = loginPage({
          message: 'Too many attempts. Wait 15 minutes, then try again.',
          status: 429,
        });
        res.setHeader('Retry-After', String(Math.ceil(ATTEMPT_WINDOW_MS / 1000)));
        return send(res, page.status, 'text/html; charset=utf-8', page.html);
      }

      readForm(req).then((form) => {
        const suppliedUsername = form.get('username') || '';
        const suppliedPassword = form.get('password') || '';
        const safeNext = normalizeReturnPath(form.get('next'));
        const usernameMatches = constantTimeTextEqual(suppliedUsername, config.username);
        const passwordMatches = constantTimeTextEqual(suppliedPassword, config.password);

        if (!usernameMatches || !passwordMatches) {
          recordFailure(address);
          authPageHeaders(res);
          const page = loginPage({
            next: safeNext,
            message: 'Account name or password is incorrect.',
            status: 401,
          });
          send(res, page.status, 'text/html; charset=utf-8', page.html);
          return;
        }

        attempts.delete(address);
        res.setHeader('Set-Cookie', sessionCookie(req, config, now()));
        redirect(res, safeNext);
      }).catch(() => {
        sendJson(res, 400, { error: 'Invalid sign-in request.' });
      });
      return undefined;
    }

    if (path === '/login' && (req.method === 'GET' || req.method === 'HEAD')) {
      if (isAuthenticated(req)) return redirect(res, '/', 302);
      authPageHeaders(res);
      const page = loginPage({ next: loginReturnTarget(req) });
      return send(res, page.status, 'text/html; charset=utf-8', req.method === 'HEAD' ? '' : page.html);
    }

    if (isAuthenticated(req)) return next();

    if ((req.method === 'GET' || req.method === 'HEAD') && (path === '/' || acceptsHtml(req))) {
      if (path === '/') {
        authPageHeaders(res);
        const page = loginPage({ next: requestTarget(req) });
        return send(res, page.status, 'text/html; charset=utf-8', req.method === 'HEAD' ? '' : page.html);
      }
      const destination = `/login?next=${encodeURIComponent(requestTarget(req))}`;
      return redirect(res, destination, 302);
    }

    return sendJson(res, 401, { error: 'Authentication required.' });
  };
}

export function passwordProtectionPlugin() {
  return {
    name: 'gev-password-protection',
    enforce: 'pre',
    configureServer(server) {
      server.middlewares.use(createAuthGate());
    },
  };
}
