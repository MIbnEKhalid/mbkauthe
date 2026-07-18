import request from 'supertest';
import express from 'express';
import { engine } from 'express-handlebars';
import path from 'path';
import { fileURLToPath } from 'url';
import { readFile } from 'fs/promises';
import { jest } from '@jest/globals';
import speakeasy from 'speakeasy';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

process.env.test = 'dev';
process.env.env = 'dev';

// Inject a self-contained config BEFORE any module import. dotenv does not
// override pre-set env vars, so this wins over the repo .env. An in-memory
// SQLite database gives every run a clean, isolated schema.
process.env.mbkautheVar = JSON.stringify({
  APP_NAME: 'mbkauthe',
  Main_SECRET_TOKEN: 'integration-main-secret-token',
  SESSION_SECRET_KEY: 'integration-session-secret-key',
  IS_DEPLOYED: 'false',
  DOMAIN: 'localhost',
  DB_TYPE: 'sqlite',
  SQLITE_PATH: ':memory:',
  // Enabled globally; it only takes effect for users with a TwoFA row.
  MBKAUTH_TWO_FA_ENABLE: 'true',
  COOKIE_EXPIRE_TIME: 2,
  MAX_SESSIONS_PER_USER: 5
});

const { default: router } = await import('../main.js');
const { packageJson, mbkautheVar, hashPassword, hashApiToken } = await import('../config/index.js');
const { encryptSessionId } = await import('../config/cookies.js');
const { dblogin } = await import('../pool.js');
const { checkRolePermission, strictValidateSession } = await import('../middleware/auth.js');
const { ErrorCodes } = await import('../utils/errors.js');

const SCHEMA_PATH = path.join(__dirname, '../../docs/schema/db.sqlite.sql');

const viewsPath = path.join(__dirname, '../../views');

const handlebarsHelpers = {
  eq: (a, b) => a === b,
  encodeURIComponent: (str) => encodeURIComponent(str),
  formatTimestamp: (timestamp) => new Date(timestamp).toLocaleString(),
  jsonStringify: (context) => JSON.stringify(context),
  json: (obj) => JSON.stringify(obj, null, 2),
  objectEntries: (obj) => {
    if (!obj || typeof obj !== 'object') return [];
    return Object.entries(obj).map(([key, value]) => ({ key, value }));
  },
  cacheBuster: () => `?v=${packageJson.version}`
};

const app = express();
app.set('views', [viewsPath]);
app.engine('handlebars', engine({
  defaultLayout: false,
  cache: true,
  partialsDir: [
    viewsPath,
    path.join(viewsPath, 'Error'),
  ],
  helpers: handlebarsHelpers
}));
app.set('view engine', 'handlebars');
app.use(router);

// ---- console silencing (same pattern as test.spec.js) ----
const shouldSilenceConsole = (args) => {
  const [firstArg = ''] = args;
  const text = typeof firstArg === 'string' ? firstArg : '';
  return text.includes('[mbkauthe]');
};

const originalConsoleLog = console.log;
const originalConsoleWarn = console.warn;
const originalConsoleError = console.error;

beforeAll(async () => {
  jest.spyOn(console, 'log').mockImplementation((...args) => {
    if (!shouldSilenceConsole(args)) originalConsoleLog(...args);
  });
  jest.spyOn(console, 'warn').mockImplementation((...args) => {
    if (!shouldSilenceConsole(args)) originalConsoleWarn(...args);
  });
  jest.spyOn(console, 'error').mockImplementation((...args) => {
    if (!shouldSilenceConsole(args)) originalConsoleError(...args);
  });

  // Apply the real schema to the in-memory database.
  const schemaSql = await readFile(SCHEMA_PATH, 'utf8');
  dblogin.execScript(schemaSql);
});

afterAll(async () => {
  jest.restoreAllMocks();
  await dblogin.end().catch(() => {});
});

// ---- test helpers ----

const PASSWORD = 'integration-password-123';
const BROWSER_UA = 'Mozilla/5.0 (integration-test)';

// Distinct client IPs per login/flow so per-IP rate limiters never trip.
// main.js enables trust proxy in test mode, so X-Forwarded-For becomes req.ip.
let ipCounter = 0;
const nextIp = () => {
  ipCounter += 1;
  return `10.9.${Math.floor(ipCounter / 200)}.${(ipCounter % 200) + 1}`;
};

/** Minimal cookie jar: stores name=value pairs, honors clears. */
class CookieJar {
  constructor() {
    this.cookies = new Map();
  }

  store(setCookies = []) {
    for (const cookieStr of setCookies || []) {
      const [pair] = cookieStr.split(';');
      const eq = pair.indexOf('=');
      if (eq < 0) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1);
      if (value === '' || /expires=thu, 01 jan 1970/i.test(cookieStr)) {
        this.cookies.delete(name);
      } else {
        this.cookies.set(name, value);
      }
    }
  }

  delete(name) {
    this.cookies.delete(name);
  }

  has(name) {
    return this.cookies.has(name);
  }

  header() {
    return [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

async function createUser(username, {
  role = 'NormalUser',
  active = 1,
  allowedApps = ['Portal', 'mbkauthe'],
  fullName = null,
  twoFASecret = null,
  twoFAStatus = 0
} = {}) {
  await dblogin.query(
    `INSERT INTO "Users" ("UserName", "PasswordEnc", "Role", "Active", "AllowedApps", "FullName")
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [username, hashPassword(PASSWORD, username), role, active, JSON.stringify(allowedApps), fullName || `Full ${username}`]
  );
  if (twoFASecret) {
    await dblogin.query(
      `INSERT INTO "TwoFA" ("UserName", "TwoFAStatus", "TwoFASecret") VALUES ($1, $2, $3)`,
      [username, twoFAStatus, twoFASecret]
    );
  }
}

/** POST /mbkauthe/api/login and absorb the returned cookies into the jar. */
async function login(username, { jar = new CookieJar(), ip = nextIp(), ua = BROWSER_UA, password = PASSWORD, redirect } = {}) {
  const req = request(app)
    .post('/mbkauthe/api/login')
    .set('X-Forwarded-For', ip)
    .set('User-Agent', ua);
  if (jar.header()) req.set('Cookie', jar.header());
  const res = await req.send({ username, password, ...(redirect ? { redirect } : {}) });
  jar.store(res.headers['set-cookie']);
  return { res, jar, ip, ua };
}

function jarGet(pathname, jar, { ip = nextIp(), ua = BROWSER_UA, accept = 'text/html' } = {}) {
  const req = request(app)
    .get(pathname)
    .set('X-Forwarded-For', ip)
    .set('User-Agent', ua)
    .set('Accept', accept)
    .redirects(0);
  if (jar && jar.header()) req.set('Cookie', jar.header());
  return req;
}

function jarPost(pathname, jar, { ip = nextIp(), ua = BROWSER_UA } = {}) {
  const req = request(app)
    .post(pathname)
    .set('X-Forwarded-For', ip)
    .set('User-Agent', ua);
  if (jar && jar.header()) req.set('Cookie', jar.header());
  return req;
}

/** JSON-flavoured GET (curl UA) so auth failures come back as JSON errors. */
function jsonGet(pathname, jar, opts = {}) {
  return jarGet(pathname, jar, { ...opts, ua: 'curl/8.0.1', accept: '*/*' });
}

async function getAppSessionId(username) {
  const result = await dblogin.query(
    'SELECT id FROM "Sessions" WHERE "UserName" = $1 ORDER BY created_at DESC',
    [username]
  );
  return result.rows[0]?.id || null;
}

async function countAppSessions(username) {
  const result = await dblogin.query(
    'SELECT COUNT(*) AS count FROM "Sessions" WHERE "UserName" = $1',
    [username]
  );
  return Number(result.rows[0].count);
}

const CSRF_RE = /name="_csrf"[^>]*value="([^"]+)"/i;

/** A 6-digit code guaranteed NOT to validate for the secret right now. */
function wrongTotpToken(secret) {
  const now = Math.floor(Date.now() / 1000);
  const valid = new Set([-1, 0, 1].map((w) =>
    speakeasy.totp({ secret, encoding: 'base32', time: now + w * 30 })
  ));
  for (const candidate of ['000000', '111111', '222222', '333333']) {
    if (!valid.has(candidate)) return candidate;
  }
  throw new Error('unreachable');
}

// =====================================================================
// 1. Authenticated login flow (login -> protected route -> logout)
// =====================================================================
describe('Login API with seeded users', () => {
  test('valid credentials log in and create an app session', async () => {
    await createUser('flow.valid');
    const { res } = await login('flow.valid');

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ success: true, message: 'Login successful' });
    expect(res.body.twoFactorRequired).toBeUndefined();

    const setCookies = (res.headers['set-cookie'] || []).join('\n');
    expect(setCookies).toContain('mbkauthe.sid=');
    expect(setCookies).toContain('sessionId=');
    expect(setCookies).toContain('fullName=');

    expect(await countAppSessions('flow.valid')).toBe(1);
  });

  test('wrong password is rejected with INCORRECT_PASSWORD', async () => {
    await createUser('flow.wrongpw');
    const { res } = await login('flow.wrongpw', { password: 'definitely-wrong-pw' });

    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.INCORRECT_PASSWORD);
    expect(await countAppSessions('flow.wrongpw')).toBe(0);
  });

  test('unknown user is rejected with INVALID_CREDENTIALS', async () => {
    const { res } = await login('flow.does.not.exist');

    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.INVALID_CREDENTIALS);
  });

  test('inactive account is rejected with ACCOUNT_INACTIVE', async () => {
    await createUser('flow.inactive', { active: 0 });
    const { res } = await login('flow.inactive');

    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.ACCOUNT_INACTIVE);
  });

  test('user without this app in AllowedApps is rejected with APP_NOT_AUTHORIZED', async () => {
    await createUser('flow.noapp', { allowedApps: ['SomeOtherApp'] });
    const { res } = await login('flow.noapp');

    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.APP_NOT_AUTHORIZED);
  });

  test('safe redirect is echoed back; open redirect is dropped', async () => {
    await createUser('flow.redirect');
    const safe = await login('flow.redirect', { redirect: '/app/dashboard' });
    expect(safe.res.status).toBe(200);
    expect(safe.res.body.redirectUrl).toBe('/app/dashboard');

    const unsafe = await login('flow.redirect', { redirect: '//evil.example.com' });
    expect(unsafe.res.status).toBe(200);
    expect(unsafe.res.body.redirectUrl).toBeUndefined();
  });

  test('logged-in session reaches the protected /test page and can log out', async () => {
    await createUser('flow.session');
    const { jar, ua } = await login('flow.session');

    // Protected page renders with the user's data
    const page = await jarGet('/mbkauthe/test', jar, { ua });
    expect(page.status).toBe(200);
    expect(page.text).toContain('flow.session');

    // Protected POST works too
    const post = await jarPost('/mbkauthe/test', jar, { ua });
    expect(post.status).toBe(200);
    expect(post.body).toMatchObject({ success: true });

    // checkSession reports valid with an expiry
    const check = await jsonGet('/mbkauthe/api/checkSession', jar);
    expect(check.status).toBe(200);
    expect(check.body.sessionValid).toBe(true);
    expect(check.body.expiry).toEqual(expect.any(String));

    // Logout deletes the app session and clears cookies
    const logout = await jarPost('/mbkauthe/api/logout', jar, { ua });
    expect(logout.status).toBe(200);
    expect(logout.body).toMatchObject({ success: true });
    jar.store(logout.headers['set-cookie']);

    expect(await countAppSessions('flow.session')).toBe(0);

    // Session is gone: protected route now redirects to login
    const after = await jarGet('/mbkauthe/test', jar, { ua });
    expect(after.status).toBe(302);
    expect(after.headers.location).toContain('/mbkauthe/login');
  });

  test('POST /api/checkSession and /api/verifySession accept a real session id (raw and encrypted)', async () => {
    await createUser('flow.verify');
    const { jar } = await login('flow.verify');
    const sessionId = await getAppSessionId('flow.verify');
    expect(sessionId).toBeTruthy();

    const rawCheck = await jarPost('/mbkauthe/api/checkSession', jar).send({ sessionId });
    expect(rawCheck.status).toBe(200);
    expect(rawCheck.body.sessionValid).toBe(true);
    expect(rawCheck.body.expiry).toEqual(expect.any(String));

    const encrypted = encryptSessionId(sessionId);
    const encVerify = await jarPost('/mbkauthe/api/verifySession', jar)
      .send({ sessionId: encrypted, isEncrypt: true });
    expect(encVerify.status).toBe(200);
    expect(encVerify.body.valid).toBe(true);
  });

  test('session restoration middleware rebuilds the session from the encrypted sessionId cookie', async () => {
    await createUser('flow.restore');
    const { jar, ua } = await login('flow.restore');

    // Drop the express-session cookie, keep the encrypted sessionId cookie.
    jar.delete('mbkauthe.sid');
    expect(jar.has('sessionId')).toBe(true);

    const page = await jarGet('/mbkauthe/test', jar, { ua });
    expect(page.status).toBe(200);
    expect(page.text).toContain('flow.restore');
  });

  test('login enforces MAX_SESSIONS_PER_USER by pruning oldest sessions', async () => {
    await createUser('flow.maxsessions');
    for (let i = 0; i < 6; i += 1) {
      const { res } = await login('flow.maxsessions');
      expect(res.status).toBe(200);
    }
    expect(await countAppSessions('flow.maxsessions')).toBe(mbkautheVar.MAX_SESSIONS_PER_USER);
  });
});

// =====================================================================
// 2. Session-validation edge cases (specific error codes)
// =====================================================================
describe('Session validation edge cases', () => {
  test('expired app session returns 401 SESSION_EXPIRED', async () => {
    await createUser('edge.expired');
    const { jar } = await login('edge.expired');

    await dblogin.query(
      `UPDATE "Sessions" SET expires_at = '2020-01-01 00:00:00' WHERE "UserName" = $1`,
      ['edge.expired']
    );

    const res = await jsonGet('/mbkauthe/test', jar);
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.SESSION_EXPIRED);
  });

  test('deleted app session returns 401 SESSION_INVALID for API clients', async () => {
    await createUser('edge.deleted');
    const { jar } = await login('edge.deleted');

    await dblogin.query('DELETE FROM "Sessions" WHERE "UserName" = $1', ['edge.deleted']);

    const res = await jsonGet('/mbkauthe/test', jar);
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.SESSION_INVALID);
  });

  test('account deactivated mid-session returns 401 ACCOUNT_INACTIVE', async () => {
    await createUser('edge.deactivated');
    const { jar } = await login('edge.deactivated');

    await dblogin.query('UPDATE "Users" SET "Active" = 0 WHERE "UserName" = $1', ['edge.deactivated']);

    const res = await jsonGet('/mbkauthe/test', jar);
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.ACCOUNT_INACTIVE);
  });

  test('app access revoked mid-session returns 401 APP_NOT_AUTHORIZED', async () => {
    await createUser('edge.revoked');
    const { jar } = await login('edge.revoked');

    await dblogin.query(
      `UPDATE "Users" SET "AllowedApps" = '["SomeOtherApp"]' WHERE "UserName" = $1`,
      ['edge.revoked']
    );

    const res = await jsonGet('/mbkauthe/test', jar);
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.APP_NOT_AUTHORIZED);
  });

  test('non-UUID sessionId inside the stored session returns 401 SESSION_EXPIRED', async () => {
    await createUser('edge.corrupt');
    const { jar } = await login('edge.corrupt');

    // Corrupt the sessionId inside the express-session store row.
    const stored = await dblogin.query('SELECT sid, sess FROM "session"');
    const row = stored.rows.find((r) => String(r.sess).includes('"username":"edge.corrupt"'));
    expect(row).toBeDefined();
    const sess = JSON.parse(row.sess);
    sess.user.sessionId = 'not-a-uuid';
    await dblogin.query('UPDATE "session" SET sess = $1 WHERE sid = $2', [JSON.stringify(sess), row.sid]);

    const res = await jsonGet('/mbkauthe/test', jar);
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.SESSION_EXPIRED);
  });

  test('expired session for a browser client redirects to login with reason', async () => {
    await createUser('edge.browser');
    const { jar, ua } = await login('edge.browser');

    await dblogin.query('DELETE FROM "Sessions" WHERE "UserName" = $1', ['edge.browser']);

    const res = await jarGet('/mbkauthe/test', jar, { ua });
    // HTML clients get the rendered "Session Expired" error page (401)
    expect(res.status).toBe(401);
    expect(res.text).toContain('Session Expired');
  });
});

// =====================================================================
// 3. API token authentication
// =====================================================================
describe('API token authentication', () => {
  async function createApiToken(username, { scope = 'read-only', allowedApps = null, name = 'test-token' } = {}) {
    const token = `mbk_${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;
    await dblogin.query(
      `INSERT INTO "ApiTokens" ("UserName", "Name", "TokenHash", "Prefix", "Permissions")
       VALUES ($1, $2, $3, $4, $5)`,
      [username, name, hashApiToken(token), 'mbk_', JSON.stringify({ scope, allowedApps })]
    );
    return token;
  }

  function bearerGet(pathname, token, { ip = nextIp() } = {}) {
    return request(app)
      .get(pathname)
      .set('X-Forwarded-For', ip)
      .set('Authorization', `Bearer ${token}`)
      .redirects(0);
  }

  function bearerPost(pathname, token, { ip = nextIp() } = {}) {
    return request(app)
      .post(pathname)
      .set('X-Forwarded-For', ip)
      .set('Authorization', `Bearer ${token}`);
  }

  test('valid read-only token authenticates GET requests', async () => {
    await createUser('token.reader');
    const token = await createApiToken('token.reader');

    const res = await bearerGet('/mbkauthe/test', token);
    expect(res.status).toBe(200);
    expect(res.text).toContain('token.reader');
  });

  test('read-only token is rejected on POST with TOKEN_SCOPE_INSUFFICIENT', async () => {
    await createUser('token.readonly');
    const token = await createApiToken('token.readonly');

    const res = await bearerPost('/mbkauthe/test', token).send({});
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.TOKEN_SCOPE_INSUFFICIENT);
    expect(res.body.tokenScope).toBe('read-only');
  });

  test('write-scope token is allowed on POST', async () => {
    await createUser('token.writer');
    const token = await createApiToken('token.writer', { scope: 'write' });

    const res = await bearerPost('/mbkauthe/test', token).send({});
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ success: true });
  });

  test('expired token returns 401 API_TOKEN_EXPIRED', async () => {
    await createUser('token.expired');
    const token = await createApiToken('token.expired');
    // CHECK constraint requires ExpiresAt > CreatedAt, so backdate both.
    await dblogin.query(
      `UPDATE "ApiTokens" SET "CreatedAt" = '2020-01-01 00:00:00', "ExpiresAt" = '2020-01-02 00:00:00'
       WHERE "UserName" = $1`,
      ['token.expired']
    );

    const res = await bearerGet('/mbkauthe/test', token);
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.API_TOKEN_EXPIRED);
  });

  test('unknown mbk_ token returns 401 INVALID_AUTH_TOKEN', async () => {
    const res = await bearerGet('/mbkauthe/test', 'mbk_this_token_does_not_exist');
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.INVALID_AUTH_TOKEN);
  });

  test('non-mbk bearer value returns 401 INVALID_AUTH_TOKEN', async () => {
    const res = await bearerGet('/mbkauthe/test', 'some-random-string');
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.INVALID_AUTH_TOKEN);
  });

  test('token of an inactive user returns 401 ACCOUNT_INACTIVE', async () => {
    await createUser('token.inactive', { active: 0 });
    const token = await createApiToken('token.inactive');

    const res = await bearerGet('/mbkauthe/test', token);
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.ACCOUNT_INACTIVE);
  });

  test('wildcard token works only when the user has the app', async () => {
    await createUser('token.wild.ok');
    const okToken = await createApiToken('token.wild.ok', { allowedApps: ['*'] });
    const okRes = await bearerGet('/mbkauthe/test', okToken);
    expect(okRes.status).toBe(200);

    await createUser('token.wild.noapp', { allowedApps: ['SomeOtherApp'] });
    const badToken = await createApiToken('token.wild.noapp', { allowedApps: ['*'] });
    const badRes = await bearerGet('/mbkauthe/test', badToken);
    expect(badRes.status).toBe(401);
    expect(badRes.body).toHaveProperty('errorCode', ErrorCodes.APP_NOT_AUTHORIZED);
  });

  test('token allowedApps overrides user apps and blocks unlisted apps', async () => {
    await createUser('token.scoped');
    const token = await createApiToken('token.scoped', { allowedApps: ['some-other-app'] });

    const res = await bearerGet('/mbkauthe/test', token);
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.APP_NOT_AUTHORIZED);
  });

  test('strictValidateSession rejects any bearer authentication', async () => {
    const strictApp = express();
    strictApp.get('/strict', strictValidateSession, (req, res) => res.json({ ok: true }));

    const res = await request(strictApp)
      .get('/strict')
      .set('Authorization', 'Bearer mbk_anything');

    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.INVALID_AUTH_TOKEN);
    expect(res.body.message).toContain('not allowed');
  });
});

// =====================================================================
// 4. Role permission middleware
// =====================================================================
describe('Role permission middleware', () => {
  test('SuperAdmin passes the SuperAdmin-only route', async () => {
    await createUser('role.admin', { role: 'SuperAdmin' });
    const { jar } = await login('role.admin');

    const res = await jsonGet('/mbkauthe/validate-superadmin', jar);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ success: true });
    expect(res.body.user.username).toBe('role.admin');
  });

  test('NormalUser gets 403 INSUFFICIENT_PERMISSIONS as JSON', async () => {
    await createUser('role.normal');
    const { jar } = await login('role.normal');

    const res = await jsonGet('/mbkauthe/validate-superadmin', jar);
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.INSUFFICIENT_PERMISSIONS);
  });

  test('NormalUser gets a rendered 403 page as a browser client', async () => {
    await createUser('role.html');
    const { jar, ua } = await login('role.html');

    const res = await jarGet('/mbkauthe/validate-superadmin', jar, { ua });
    expect(res.status).toBe(403);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.text).toContain('Access Denied');
  });

  test('unauthenticated request to a role-guarded route returns 401 SESSION_NOT_FOUND', async () => {
    const res = await jsonGet('/mbkauthe/validate-superadmin', null);
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.SESSION_NOT_FOUND);
  });

  // Direct middleware matrix for role shapes no built-in route exercises.
  describe('checkRolePermission matrix', () => {
    const buildRoleApp = () => {
      const roleApp = express();
      roleApp.use((req, res, next) => {
        const role = req.headers['x-role'];
        req.session = role ? { user: { username: 'matrix.user', role } } : {};
        next();
      });
      roleApp.get('/any', checkRolePermission('Any'), (req, res) => res.json({ ok: true }));
      roleApp.get('/guests-blocked', checkRolePermission('Any', 'Guest'), (req, res) => res.json({ ok: true }));
      roleApp.get('/multi', checkRolePermission(['Manager', 'Editor']), (req, res) => res.json({ ok: true }));
      return roleApp;
    };

    const roleGet = (pathname, role) => {
      const req = request(buildRoleApp()).get(pathname)
        .set('User-Agent', 'curl/8.0.1')
        .set('Accept', '*/*');
      if (role) req.set('X-Role', role);
      return req;
    };

    test('"Any" admits every authenticated role', async () => {
      const res = await roleGet('/any', 'NormalUser');
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ ok: true });
    });

    test('notAllowed role is rejected with ROLE_NOT_ALLOWED even under "Any"', async () => {
      const res = await roleGet('/guests-blocked', 'Guest');
      expect(res.status).toBe(403);
      expect(res.body).toHaveProperty('errorCode', ErrorCodes.ROLE_NOT_ALLOWED);
    });

    test('role arrays admit listed roles and reject others', async () => {
      const ok = await roleGet('/multi', 'Editor');
      expect(ok.status).toBe(200);

      const denied = await roleGet('/multi', 'NormalUser');
      expect(denied.status).toBe(403);
      expect(denied.body).toHaveProperty('errorCode', ErrorCodes.INSUFFICIENT_PERMISSIONS);
    });

    test('SuperAdmin bypasses both notAllowed and role lists', async () => {
      const blocked = await roleGet('/guests-blocked', 'SuperAdmin');
      expect(blocked.status).toBe(200);

      const multi = await roleGet('/multi', 'SuperAdmin');
      expect(multi.status).toBe(200);
    });

    test('missing user is rejected with SESSION_NOT_FOUND', async () => {
      const res = await roleGet('/any', null);
      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('errorCode', ErrorCodes.SESSION_NOT_FOUND);
    });
  });
});

// =====================================================================
// 5. 2FA success path (+ trusted device skip)
// =====================================================================
describe('Two-factor authentication', () => {
  test('full 2FA login flow with a valid TOTP token and trusted-device skip on re-login', async () => {
    const secret = speakeasy.generateSecret({ length: 20 }).base32;
    await createUser('twofa.full', { twoFASecret: secret, twoFAStatus: 1 });

    const ip = nextIp();
    const { res: loginRes, jar, ua } = await login('twofa.full', { ip });
    expect(loginRes.status).toBe(200);
    expect(loginRes.body).toMatchObject({ success: true, twoFactorRequired: true });
    // No app session yet — only after 2FA completes.
    expect(await countAppSessions('twofa.full')).toBe(0);

    // The 2FA page renders for the pre-auth session and provides the CSRF token.
    const page = await jarGet('/mbkauthe/2fa', jar, { ip, ua });
    expect(page.status).toBe(200);
    jar.store(page.headers['set-cookie']);
    const csrfToken = page.text.match(CSRF_RE)?.[1];
    expect(csrfToken).toBeTruthy();

    const token = speakeasy.totp({ secret, encoding: 'base32' });
    const verify = await jarPost('/mbkauthe/api/verify-2fa', jar, { ip, ua })
      .send({ token, _csrf: csrfToken, trustDevice: true });
    expect(verify.status).toBe(200);
    expect(verify.body).toMatchObject({ success: true });
    jar.store(verify.headers['set-cookie']);

    expect(await countAppSessions('twofa.full')).toBe(1);
    expect(jar.has('device_token')).toBe(true);

    // Session works on protected routes
    const protectedPage = await jarGet('/mbkauthe/test', jar, { ip, ua });
    expect(protectedPage.status).toBe(200);
    expect(protectedPage.text).toContain('twofa.full');

    // Re-login on the trusted device skips 2FA entirely.
    const relogin = await login('twofa.full', { jar, ip, ua });
    expect(relogin.res.status).toBe(200);
    expect(relogin.res.body).toMatchObject({ success: true });
    expect(relogin.res.body.twoFactorRequired).toBeUndefined();
  });

  test('invalid TOTP token is rejected with TWO_FA_INVALID_TOKEN and no session is created', async () => {
    const secret = speakeasy.generateSecret({ length: 20 }).base32;
    await createUser('twofa.badtoken', { twoFASecret: secret, twoFAStatus: 1 });

    const ip = nextIp();
    const { res: loginRes, jar, ua } = await login('twofa.badtoken', { ip });
    expect(loginRes.body.twoFactorRequired).toBe(true);

    const page = await jarGet('/mbkauthe/2fa', jar, { ip, ua });
    jar.store(page.headers['set-cookie']);
    const csrfToken = page.text.match(CSRF_RE)?.[1];

    const verify = await jarPost('/mbkauthe/api/verify-2fa', jar, { ip, ua })
      .send({ token: wrongTotpToken(secret), _csrf: csrfToken });
    expect(verify.status).toBe(401);
    expect(verify.body).toHaveProperty('errorCode', ErrorCodes.TWO_FA_INVALID_TOKEN);
    expect(await countAppSessions('twofa.badtoken')).toBe(0);
  });

  test('user with 2FA disabled logs in directly even though 2FA is enabled globally', async () => {
    const secret = speakeasy.generateSecret({ length: 20 }).base32;
    await createUser('twofa.disabled', { twoFASecret: secret, twoFAStatus: 0 });

    const { res } = await login('twofa.disabled');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ success: true });
    expect(res.body.twoFactorRequired).toBeUndefined();
    expect(await countAppSessions('twofa.disabled')).toBe(1);
  });
});

// =====================================================================
// 6. OAuth callback state validation
// =====================================================================
describe('OAuth callback state validation', () => {
  test.each([
    ['github', 'missing state', ''],
    ['github', 'mismatched state', '?state=forged-state-value'],
    ['google', 'mismatched state', '?state=forged-state-value'],
  ])('%s callback with %s is rejected with 403', async (provider, _label, query) => {
    const res = await request(app)
      .get(`/mbkauthe/api/${provider}/login/callback${query}`)
      .set('X-Forwarded-For', nextIp())
      .set('User-Agent', BROWSER_UA)
      .redirects(0);

    expect(res.status).toBe(403);
    expect(res.text).toContain('Invalid Request');
  });

  test('OAuth initiation is refused when the provider is disabled', async () => {
    const res = await request(app)
      .get('/mbkauthe/api/github/login')
      .set('X-Forwarded-For', nextIp())
      .set('User-Agent', BROWSER_UA)
      .redirects(0);

    expect(res.status).toBe(403);
    expect(res.text).toContain('GitHub Login Disabled');
  });
});

// =====================================================================
// Multi-account cookies + admin session termination
// =====================================================================
describe('Multi-account session management', () => {
  test('account-sessions lists the remembered account for the same device fingerprint', async () => {
    await createUser('multi.list');
    const { jar, ua } = await login('multi.list');

    // Same UA as login — the account-list cookie is fingerprinted by user-agent.
    const res = await jarGet('/mbkauthe/api/account-sessions', jar, { ua, accept: 'application/json' });
    expect(res.status).toBe(200);
    expect(res.body.accounts).toHaveLength(1);
    expect(res.body.accounts[0]).toMatchObject({ username: 'multi.list', isCurrent: true });
  });

  test('a different user-agent invalidates the account-list fingerprint', async () => {
    await createUser('multi.fingerprint');
    const { jar } = await login('multi.fingerprint', { ua: 'Mozilla/5.0 (device-one)' });

    const res = await jsonGet('/mbkauthe/api/account-sessions', jar, { ua: 'Mozilla/5.0 (device-two)' });
    expect(res.status).toBe(200);
    expect(res.body.accounts).toHaveLength(0);
  });

  test('switch-session activates a remembered account', async () => {
    await createUser('multi.switch');
    const { jar, ua } = await login('multi.switch');
    const sessionId = await getAppSessionId('multi.switch');

    const res = await jarPost('/mbkauthe/api/switch-session', jar, { ua })
      .send({ sessionId, redirect: '/after-switch' });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      success: true,
      username: 'multi.switch',
      redirect: '/after-switch'
    });
  });

  test('switch-session refuses a session not remembered on this device', async () => {
    await createUser('multi.foreign');
    const { jar, ua } = await login('multi.foreign');

    const res = await jarPost('/mbkauthe/api/switch-session', jar, { ua })
      .send({ sessionId: '00000000-0000-4000-8000-000000000000' });
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('errorCode', ErrorCodes.SESSION_NOT_FOUND);
  });

  test('logout-all removes every remembered session for the device', async () => {
    await createUser('multi.all.one');
    await createUser('multi.all.two');
    const ua = 'Mozilla/5.0 (logout-all-device)';
    const { jar } = await login('multi.all.one', { ua });
    await login('multi.all.two', { jar, ua });

    expect(await countAppSessions('multi.all.one')).toBe(1);
    expect(await countAppSessions('multi.all.two')).toBe(1);

    const res = await jarPost('/mbkauthe/api/logout-all', jar, { ua }).send({});
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ success: true });

    expect(await countAppSessions('multi.all.one')).toBe(0);
    expect(await countAppSessions('multi.all.two')).toBe(0);
  });
});

describe('Admin session termination', () => {
  test('terminateAllSessions requires the main secret token', async () => {
    const res = await request(app)
      .post('/mbkauthe/api/terminateAllSessions')
      .set('X-Forwarded-For', nextIp())
      .set('Authorization', 'Bearer wrong-secret')
      .send({});

    expect(res.status).toBe(401);
  });

  test('terminateAllSessions wipes every app session with the correct token', async () => {
    await createUser('admin.wipe');
    await login('admin.wipe');
    expect(await countAppSessions('admin.wipe')).toBe(1);

    const res = await request(app)
      .post('/mbkauthe/api/terminateAllSessions')
      .set('X-Forwarded-For', nextIp())
      .set('Authorization', `Bearer ${mbkautheVar.Main_SECRET_TOKEN}`)
      .send({});

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ success: true });
    expect(await countAppSessions('admin.wipe')).toBe(0);
  });
});
