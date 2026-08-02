// Integration tests for the CLI / device-flow auth (browser-based token provisioning).
//
// Exercises the full flow against an in-memory SQLite database:
//   POST /api/cli/device  ->  GET /mbkauthe/cli/device/:userCode  ->  POST /api/cli/device/approve
//   ->  POST /api/cli/device/token  ->  the issued token verifies via /api/tokens/verify
//
// Mirrors the setup of integration.spec.js (real login, cookie jar, distinct IPs).

import request from 'supertest';
import express from 'express';
import { engine } from 'express-handlebars';
import path from 'path';
import { fileURLToPath } from 'url';
import { readFile } from 'fs/promises';
import { jest } from '@jest/globals';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

process.env.test = 'dev';
process.env.env = 'dev';
process.env.mbkautheVar = JSON.stringify({
  APP_NAME: 'mbkauthe',
  Main_SECRET_TOKEN: 'cli-auth-main-secret-token',
  SESSION_SECRET_KEY: 'cli-auth-session-secret-key',
  IS_DEPLOYED: 'false',
  DOMAIN: 'localhost',
  DB_TYPE: 'sqlite',
  SQLITE_PATH: ':memory:',
  MBKAUTH_TWO_FA_ENABLE: 'false',
  COOKIE_EXPIRE_TIME: 2,
  MAX_SESSIONS_PER_USER: 5
});

const { default: router } = await import('../main.js');
const { packageJson, mbkautheVar, hashPassword } = await import('../config/index.js');
const { hashApiToken } = await import('../config/security.js');
const { dblogin } = await import('../pool.js');
const { default: cliAuthRouter } = await import('../routes/cliAuth.js');
const { default: apiTokensRouter } = await import('../routes/apiTokens.js');

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
app.use(apiTokensRouter);
app.use(cliAuthRouter);

// ---- console silencing (same pattern as integration.spec.js) ----
const shouldSilenceConsole = (args) => {
  const [firstArg = ''] = args;
  const text = typeof firstArg === 'string' ? firstArg : '';
  return text.includes('[mbkauthe]');
};
const originalConsoleLog = console.log;
const originalConsoleWarn = console.warn;
const originalConsoleError = console.error;

const PASSWORD = 'cli-auth-password-123';
const BROWSER_UA = 'Mozilla/5.0 (cli-auth-test)';
let ipCounter = 0;
const nextIp = () => {
  ipCounter += 1;
  return `10.11.${Math.floor(ipCounter / 200)}.${(ipCounter % 200) + 1}`;
};

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
  header() {
    return [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

async function createUser(username, { role = 'NormalUser', active = 1, allowedApps = ['Portal', 'mbkauthe'] } = {}) {
  await dblogin.query(
    `INSERT INTO "Users" ("UserName", "PasswordEnc", "Role", "Active", "AllowedApps", "FullName")
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [username, hashPassword(PASSWORD, username), role, active, JSON.stringify(allowedApps), `Full ${username}`]
  );
}

let profileCounter = 0;
async function createProfile({ name, scope = 'read-only', allowedApps = null, expiresInDays = null, active = 1, key = null } = {}) {
  profileCounter += 1;
  const profileName = name || `profile-${profileCounter}`;
  const profileKey = key || `key${String(profileCounter).padStart(6, '0')}`; // >= 6 chars
  const { rows } = await dblogin.query(
    `INSERT INTO "ApiTokenProfiles" ("ProfileKey", "Name", "Description", "AllowedApps", "Scope", "ExpiresInDays", "Active")
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING "id", "ProfileKey"`,
    [profileKey, profileName, 'test profile', allowedApps ? JSON.stringify(allowedApps) : null, scope, expiresInDays, active]
  );
  return { id: rows[0].id, key: rows[0].ProfileKey };
}

async function login(username, { jar = new CookieJar(), ip = nextIp(), ua = BROWSER_UA, password = PASSWORD } = {}) {
  const req = request(app)
    .post('/mbkauthe/api/login')
    .set('X-Forwarded-For', ip)
    .set('User-Agent', ua);
  if (jar.header()) req.set('Cookie', jar.header());
  const res = await req.send({ username, password });
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

function jarPostJson(pathname, jar, body, { ip = nextIp(), ua = BROWSER_UA } = {}) {
  const req = request(app)
    .post(pathname)
    .set('X-Forwarded-For', ip)
    .set('User-Agent', ua)
    .set('Accept', 'application/json')
    .set('Content-Type', 'application/json');
  if (jar && jar.header()) req.set('Cookie', jar.header());
  return req.send(body);
}

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

  const schemaSql = await readFile(SCHEMA_PATH, 'utf8');
  dblogin.execScript(schemaSql);
});

afterAll(async () => {
  jest.restoreAllMocks();
  await dblogin.end().catch(() => {});
});
describe('POST /api/cli/device', () => {
  test('creates a device session and returns verification info', async () => {
    const { id: profileId } = await createProfile({ name: 'cli-default' });

    const res = await request(app)
      .post('/api/cli/device')
      .set('X-Forwarded-For', nextIp())
      .set('User-Agent', 'my-cli/1.0')
      .send({ clientName: 'my-cli', profileId });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.deviceCode).toMatch(/^[0-9a-f]{48}$/);
    expect(res.body.userCode).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    expect(res.body.verificationUrl).toContain(`/mbkauthe/cli/device/${res.body.userCode}`);
    expect(res.body.interval).toBe(5);
    expect(res.body.expiresIn).toBeGreaterThan(0);
    expect(res.body.profile.name).toBe('cli-default');
    expect(res.body.profile.scope).toBe('read-only');
  });

  test('starts login by profileKey', async () => {
    const { id, key } = await createProfile({ name: 'key-flow', scope: 'write' });

    const res = await request(app)
      .post('/api/cli/device')
      .set('X-Forwarded-For', nextIp())
      .set('User-Agent', 'key-cli/1.0')
      .send({ clientName: 'key-cli', profileKey: key });

    expect(res.status).toBe(201);
    expect(res.body.profile.key).toBe(key);
    expect(res.body.profile.id).toBe(id);
  });

  test('rejects a missing clientName', async () => {
    const { id: profileId } = await createProfile();
    const res = await request(app)
      .post('/api/cli/device')
      .set('X-Forwarded-For', nextIp())
      .send({ profileId });
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('clientName');
  });

  test('rejects an invalid / inactive profile', async () => {
    const { id: inactiveId } = await createProfile({ name: 'inactive-profile', active: 0 });
    const res = await request(app)
      .post('/api/cli/device')
      .set('X-Forwarded-For', nextIp())
      .send({ clientName: 'cli', profileId: inactiveId });
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('profile');

    const missing = await request(app)
      .post('/api/cli/device')
      .set('X-Forwarded-For', nextIp())
      .send({ clientName: 'cli', profileId: 999999 });
    expect(missing.status).toBe(400);
  });
});

describe('CLI device flow (happy path)', () => {
  test('device -> login -> approve -> poll -> verify token', async () => {
    await createUser('cliuser');
    const { id: profileId } = await createProfile({ name: 'happy-flow', scope: 'write', allowedApps: ['Portal'], expiresInDays: 7 });

    // 1. CLI requests a login
    const deviceRes = await request(app)
      .post('/api/cli/device')
      .set('X-Forwarded-For', nextIp())
      .set('User-Agent', 'happy-cli/1.0')
      .send({ clientName: 'happy-cli', profileId });
    expect(deviceRes.status).toBe(201);
    const { userCode, deviceCode } = deviceRes.body;

    // 2. Poll before approval -> pending
    const pendingRes = await request(app)
      .post('/api/cli/device/token')
      .set('X-Forwarded-For', nextIp())
      .set('User-Agent', 'happy-cli/1.0')
      .send({ deviceCode });
    expect(pendingRes.status).toBe(200);
    expect(pendingRes.body.status).toBe('pending');

    // 3. Approval page requires login (redirects to /mbkauthe/login)
    const anonPage = await jarGet(`/mbkauthe/cli/device/${userCode}`, null);
    expect(anonPage.status).toBe(302);
    expect(anonPage.headers.location).toContain('/mbkauthe/login');

    // 4. Login and view the approval page
    const { jar } = await login('cliuser');
    const page = await jarGet(`/mbkauthe/cli/device/${userCode}`, jar);
    expect(page.status).toBe(200);
    expect(page.text).toContain(userCode);
    expect(page.text).toContain('happy-cli');

    // 5. Approve
    const approveRes = await jarPostJson('/api/cli/device/approve', jar, { userCode, action: 'approve' });
    expect(approveRes.status).toBe(200);
    expect(approveRes.body.status).toBe('approved');

    // 6. Poll -> token delivered (once)
    const pollRes = await request(app)
      .post('/api/cli/device/token')
      .set('X-Forwarded-For', nextIp())
      .set('User-Agent', 'happy-cli/1.0')
      .send({ deviceCode });
    expect(pollRes.status).toBe(200);
    expect(pollRes.body.status).toBe('approved');
    expect(pollRes.body.token).toMatch(/^mbk_/);
    expect(pollRes.body.username).toBe('cliuser');
    const issuedToken = pollRes.body.token;

    // 7. Poll again -> completed, no second token
    const againRes = await request(app)
      .post('/api/cli/device/token')
      .set('X-Forwarded-For', nextIp())
      .set('User-Agent', 'happy-cli/1.0')
      .send({ deviceCode });
    expect(againRes.status).toBe(200);
    expect(againRes.body.status).toBe('completed');
    expect(againRes.body.token).toBeUndefined();

    // 8. The issued token verifies with the profile's scope + allowed apps
    const verifyRes = await request(app)
      .post('/api/tokens/verify')
      .set('Authorization', `Bearer ${issuedToken}`);
    expect(verifyRes.status).toBe(200);
    expect(verifyRes.body.username).toBe('cliuser');
    expect(verifyRes.body.scope).toBe('write');
    expect(verifyRes.body.allowedApps).toEqual(['Portal']);
  });

  test('deny flow returns denied to the CLI', async () => {
    await createUser('denyuser');
    const { id: profileId } = await createProfile({ name: 'deny-flow' });

    const deviceRes = await request(app)
      .post('/api/cli/device')
      .set('X-Forwarded-For', nextIp())
      .set('User-Agent', 'deny-cli/1.0')
      .send({ clientName: 'deny-cli', profileId });
    const { userCode, deviceCode } = deviceRes.body;

    const { jar } = await login('denyuser');
    const denyRes = await jarPostJson('/api/cli/device/approve', jar, { userCode, action: 'deny' });
    expect(denyRes.status).toBe(200);
    expect(denyRes.body.status).toBe('denied');

    const pollRes = await request(app)
      .post('/api/cli/device/token')
      .set('X-Forwarded-For', nextIp())
      .set('User-Agent', 'deny-cli/1.0')
      .send({ deviceCode });
    expect(pollRes.status).toBe(200);
    expect(pollRes.body.status).toBe('denied');
    expect(pollRes.body.token).toBeUndefined();
  });

  test('expired sessions return expired to the CLI', async () => {
    const { id: profileId } = await createProfile({ name: 'expire-flow' });

    const deviceRes = await request(app)
      .post('/api/cli/device')
      .set('X-Forwarded-For', nextIp())
      .set('User-Agent', 'expire-cli/1.0')
      .send({ clientName: 'expire-cli', profileId });
    const { deviceCode } = deviceRes.body;

    // Backdate the session expiry into the past.
    await dblogin.query(
      `UPDATE "CliAuthSessions" SET "ExpiresAt" = ? WHERE "DeviceCodeHash" = ?`,
      ['2020-01-01 00:00:00', hashApiToken(deviceCode)]
    );

    const pollRes = await request(app)
      .post('/api/cli/device/token')
      .set('X-Forwarded-For', nextIp())
      .set('User-Agent', 'expire-cli/1.0')
      .send({ deviceCode });
    expect(pollRes.status).toBe(200);
    expect(pollRes.body.status).toBe('expired');
  });

  test('approve requires an authenticated session', async () => {
    const { id: profileId } = await createProfile({ name: 'unauth-flow' });
    const deviceRes = await request(app)
      .post('/api/cli/device')
      .set('X-Forwarded-For', nextIp())
      .set('User-Agent', 'unauth-cli/1.0')
      .send({ clientName: 'unauth-cli', profileId });
    const { userCode } = deviceRes.body;

    const res = await jarPostJson('/api/cli/device/approve', null, { userCode, action: 'approve' });
    expect(res.status).toBe(401);
  });
});
