import request from 'supertest';
import express from 'express';
import { engine } from 'express-handlebars';
import path from 'path';
import { fileURLToPath } from 'url';
import { jest } from '@jest/globals';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

process.env.test = 'dev';
process.env.env = 'dev';
process.env.dbLogs = 'true';
process.env.dbLogsCallsite = 'false';

const { default: router } = await import('./lib/main.js');
const { packageJson } = await import('./lib/config/index.js');
const {
  resolveCookieDomain,
  isAllowedOriginHostname,
  getCookieDomain,
  cachedCookieOptions
} = await import('./lib/config/cookies.js');
const { dblogin } = await import('./lib/pool.js');
const {
  attachDevQueryLogger,
  resetQueryCount,
  resetQueryLog,
  runWithRequestContext
} = await import('./lib/utils/dbQueryLogger.js');

const viewsPath = path.join(__dirname, 'views');

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
app.set('views', [
  viewsPath,
  path.join(__dirname, 'node_modules/mbkauthe/views')
]);
app.engine('handlebars', engine({
  defaultLayout: false,
  cache: true,
  partialsDir: [
    viewsPath,
    path.join(__dirname, 'node_modules/mbkauthe/views'),
    path.join(__dirname, 'node_modules/mbkauthe/views/Error'),
  ],
  helpers: handlebarsHelpers
}));
app.set('view engine', 'handlebars');
app.use(router);

const shouldSilenceConsole = (args) => {
  const [firstArg = ''] = args;
  const text = typeof firstArg === 'string' ? firstArg : '';

  return text.includes('[mbkauthe]');
};

const originalConsoleLog = console.log;
const originalConsoleWarn = console.warn;
const originalConsoleError = console.error;

beforeAll(() => {
  jest.spyOn(console, 'log').mockImplementation((...args) => {
    if (!shouldSilenceConsole(args)) {
      originalConsoleLog(...args);
    }
  });

  jest.spyOn(console, 'warn').mockImplementation((...args) => {
    if (!shouldSilenceConsole(args)) {
      originalConsoleWarn(...args);
    }
  });

  jest.spyOn(console, 'error').mockImplementation((...args) => {
    if (!shouldSilenceConsole(args)) {
      originalConsoleError(...args);
    }
  });
});

afterAll(async () => {
  jest.restoreAllMocks();
  await dblogin.end().catch(() => {});
});

// Helper to get CSRF token and cookies
const getCSRFTokenAndCookies = async () => {
  const response = await request(app).get('/mbkauthe/login');
  const html = response.text;
  const csrfMatch = html.match(/name="_csrf".*?value="([^"]+)"/i) ||
    html.match(/content="([^"]+)".*?name="_csrf"/i);

  return {
    csrfToken: csrfMatch?.[1] || '',
    cookies: response.headers['set-cookie'] || []
  };
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const createFakePool = ({ name = 'fake-db-pool' } = {}) => {
  const pool = {
    totalCount: 1,
    idleCount: 1,
    waitingCount: 0,
    options: { application_name: name },
    async connect() {
      pool.idleCount = 0;

      return {
        async query(configOrText, maybeValues) {
          const text = typeof configOrText === 'string' ? configOrText : configOrText?.text || '';
          const values = Array.isArray(maybeValues)
            ? maybeValues
            : Array.isArray(configOrText?.values)
            ? configOrText.values
            : [];

          if (text.includes('slow_table')) {
            await sleep(6);
          }

          if (text.includes('broken_table')) {
            const error = new Error('broken query');
            error.code = 'FAKE_ERR';
            throw error;
          }

          return {
            command: 'SELECT',
            rowCount: values.length ? 1 : 0,
            rows: values.length ? [{ value: values[0] }] : [],
          };
        },
        release() {
          pool.idleCount = 1;
        }
      };
    },
    async query(configOrText, maybeValues) {
      const client = await this.connect();
      try {
        return await client.query(configOrText, maybeValues);
      } finally {
        client.release();
      }
    }
  };

  attachDevQueryLogger(pool);
  return pool;
};

describe('mbkauthe Routes', () => {
  beforeEach(() => {
    resetQueryCount();
    resetQueryLog();
  });

  describe('Redirect Routes', () => {
    test('GET /login redirects to /mbkauthe/login', async () => {
      const response = await request(app)
        .get('/login')
        .redirects(0);

      expect(response.status).toBe(302);
      expect(response.headers.location).toContain('/mbkauthe/login');
    });

    test('GET /signin redirects to /mbkauthe/login', async () => {
      const response = await request(app)
        .get('/signin')
        .redirects(0);

      expect(response.status).toBe(302);
      expect(response.headers.location).toContain('/mbkauthe/login');
    });
  });

  describe('Authentication Pages', () => {
    test('GET /mbkauthe/login contains loginUsername input', async () => {
      const response = await request(app).get('/mbkauthe/login');

      expect(response.status).toBe(200);
      expect(response.text).toMatch(/id\s*=\s*["']loginUsername["']/i);
    });

    test('GET /mbkauthe/login renders csrf token field', async () => {
      const response = await request(app).get('/mbkauthe/login');

      expect(response.status).toBe(200);
      expect(response.text).toMatch(/name\s*=\s*["']_csrf["']/i);
    });

    test('GET /mbkauthe/2fa contains token input or redirects', async () => {
      const response = await request(app)
        .get('/mbkauthe/2fa')
        .redirects(0);

      if (response.status === 302) {
        expect(response.headers.location).toContain('/mbkauthe/login');
      } else {
        expect(response.status).toBe(200);
        expect(response.text).toMatch(/id\s*=\s*["']token["']/i);
      }
    });
  });

  describe('Info Pages', () => {
    test.each([
      ['/mbkauthe/info', 'info page'],
      ['/mbkauthe/i', 'info short page'],
    ])('GET %s contains CurrentVersion div', async (routePath) => {
      const response = await request(app).get(routePath);

      expect(response.status).toBe(200);
      expect(response.text).toMatch(/id\s*=\s*["']CurrentVersion["']/i);
    });

    test('GET /mbkauthe/ErrorCode contains error-603 div', async () => {
      const response = await request(app).get('/mbkauthe/ErrorCode');

      expect(response.status).toBe(200);
      expect(response.text).toMatch(/id\s*=\s*["']error-603["']/i);
    });

    test('GET /mbkauthe/db renders DB monitor filters and summary sections', async () => {
      const response = await request(app).get('/mbkauthe/db');

      expect(response.status).toBe(200);
      expect(response.text).toContain('DB Query Monitor');
      expect(response.text).toContain('Top Repeated Query Shapes');
      expect(response.text).toContain('Slowest Recent Queries');
      expect(response.text).toMatch(/name="username"/i);
      expect(response.text).toMatch(/name="url"/i);
      expect(response.text).toMatch(/name="success"/i);
    });
  });

  describe('Static Assets', () => {
    test('GET /mbkauthe/main.js returns JavaScript', async () => {
      const response = await request(app).get('/mbkauthe/main.js');

      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('javascript');
      expect(response.text).toMatch(/^window\.mbkautheConfig=/);
    });

    test('GET /icon.svg returns SVG content', async () => {
      const response = await request(app).get('/icon.svg');

      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('image/png');
    });

    test('GET /mbkauthe/bg.webp returns WEBP content', async () => {
      const response = await request(app).get('/mbkauthe/bg.webp');

      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('image/webp');
    });
  });

  describe('Protected Routes', () => {
    test('GET /mbkauthe/test responds appropriately', async () => {
      const response = await request(app).get('/mbkauthe/test');
      expect([200, 302, 401, 403, 429]).toContain(response.status);
    });

    test('GET /mbkauthe/test with curl UA returns JSON 401', async () => {
      const response = await request(app)
        .get('/mbkauthe/test')
        .set('User-Agent', 'curl/8.0.1')
        .set('Accept', '*/*');

      expect(response.status).toBe(401);
      expect(response.headers['content-type']).toContain('application/json');
      expect(response.body).toHaveProperty('success', false);
      expect(response.body).toHaveProperty('errorCode');
    });

    test('GET /mbkauthe/test with browser accept redirects to login when unauthenticated', async () => {
      const response = await request(app)
        .get('/mbkauthe/test')
        .set('User-Agent', 'Mozilla/5.0')
        .set('Accept', 'text/html')
        .redirects(0);

      expect(response.status).toBe(302);
      expect(response.headers.location).toContain('/mbkauthe/login');
      expect(response.headers.location).toContain('reason=logged_out');
    });
  });

  describe('OAuth Routes', () => {
    test('GET /mbkauthe/api/github/login handles GitHub App flow', async () => {
      const response = await request(app)
        .get('/mbkauthe/api/github/login')
        .redirects(0);

      expect([200, 302, 403, 500, 429]).toContain(response.status);

      if (response.status === 302) {
        const location = response.headers.location;
        expect(location).toMatch(/github\.com|login/);
      }
    });

    test('GET /mbkauthe/api/github/login/callback handles GitHub App callback', async () => {
      const response = await request(app).get('/mbkauthe/api/github/login/callback');
      expect([200, 302, 400, 401, 403, 429]).toContain(response.status);
    });

    test('GET /mbkauthe/api/google/login handles Google OAuth', async () => {
      const response = await request(app)
        .get('/mbkauthe/api/google/login')
        .redirects(0);

      expect([200, 302, 403, 500, 429]).toContain(response.status);

      if (response.status === 302) {
        const location = response.headers.location;
        expect(location).toMatch(/accounts\.google\.com|login/);
      }
    });

    test('GET /mbkauthe/api/google/login/callback handles callback', async () => {
      const response = await request(app).get('/mbkauthe/api/google/login/callback');
      expect([200, 302, 400, 401, 403, 429]).toContain(response.status);
    });

    test('GET /mbkauthe/api/github/login rejects unsafe redirect targets', async () => {
      const response = await request(app)
        .get('/mbkauthe/api/github/login?redirect=https://evil.example')
        .redirects(0);

      expect([200, 302, 403, 500, 429]).toContain(response.status);
      if (response.status === 302) {
        expect(response.headers.location).not.toContain('evil.example');
      }
    });
  });

  describe('API Endpoints', () => {
    test('GET /mbkauthe/db.json returns newest-first logs with summary stats and fingerprints', async () => {
      const fakePool = createFakePool({ name: 'reporting-db' });

      await runWithRequestContext(
        {
          method: 'POST',
          originalUrl: '/mbkauthe/api/login',
          url: '/mbkauthe/api/login',
          ip: '127.0.0.1',
          session: { user: { id: '1', username: 'support' } }
        },
        () => fakePool.query({ text: 'SELECT * FROM users WHERE id = $1', values: [1], name: 'userLookup' })
      );

      await sleep(4);

      await runWithRequestContext(
        {
          method: 'POST',
          originalUrl: '/mbkauthe/api/login',
          url: '/mbkauthe/api/login',
          ip: '127.0.0.1',
          session: { user: { id: '1', username: 'support' } }
        },
        () => fakePool.query({ text: 'SELECT * FROM users WHERE id = $1', values: [2], name: 'userLookup' })
      );

      await sleep(4);

      await runWithRequestContext(
        {
          method: 'GET',
          originalUrl: '/mbkauthe/api/audit',
          url: '/mbkauthe/api/audit',
          ip: '127.0.0.1',
          session: { user: { id: '2', username: 'auditor' } }
        },
        () => fakePool.query({ text: 'SELECT * FROM slow_table WHERE team_id = $1', values: [55], name: 'slowAudit' })
      );

      await sleep(4);

      await runWithRequestContext(
        {
          method: 'GET',
          originalUrl: '/mbkauthe/api/admin',
          url: '/mbkauthe/api/admin',
          ip: '127.0.0.1',
          session: { user: { id: '3', username: 'admin' } }
        },
        async () => {
          await fakePool.query({ text: 'SELECT * FROM broken_table WHERE id = $1', values: [99], name: 'brokenLookup' })
            .catch(() => {});
        }
      );

      const response = await request(app).get('/mbkauthe/db.json?limit=10');

      expect(response.status).toBe(200);
      expect(response.body.isDev).toBe(true);
      expect(response.body.queryCount).toBe(4);
      expect(response.body.summary.totalVisible).toBe(4);
      expect(response.body.summary.errorCount).toBe(1);
      expect(response.body.queryLog).toHaveLength(4);
      expect(response.body.queryLog[0].query).toContain('broken_table');
      expect(response.body.queryLog[1].query).toContain('slow_table');
      expect(response.body.queryLog[0].fingerprint).toMatch(/^[0-9a-f]{12}$/);
      expect(response.body.queryLog[0].poolWait).toMatchObject({
        source: 'pool.query',
        captured: true
      });
      expect(response.body.queryLog[0].trigger).toMatchObject({
        type: 'request',
        source: 'route'
      });
      expect(response.body.summary.slowestQueries[0].query).toContain('slow_table');
      expect(response.body.summary.repeatedGroups[0]).toMatchObject({
        count: 2,
        sampleName: 'userLookup'
      });
      expect(response.body.summary.repeatedGroups[0].fingerprint).toMatch(/^[0-9a-f]{12}$/);
    });

    test('GET /mbkauthe/db.json filters by username, url, and success', async () => {
      const fakePool = createFakePool({ name: 'filter-db' });

      await runWithRequestContext(
        {
          method: 'POST',
          originalUrl: '/mbkauthe/api/login',
          url: '/mbkauthe/api/login',
          ip: '127.0.0.1',
          session: { user: { id: '1', username: 'support' } }
        },
        () => fakePool.query({ text: 'SELECT * FROM users WHERE id = $1', values: [7], name: 'loginLookup' })
      );

      await runWithRequestContext(
        {
          method: 'GET',
          originalUrl: '/mbkauthe/api/reports',
          url: '/mbkauthe/api/reports',
          ip: '127.0.0.1',
          session: { user: { id: '2', username: 'auditor' } }
        },
        async () => {
          await fakePool.query({ text: 'SELECT * FROM broken_table WHERE id = $1', values: [8], name: 'badLookup' })
            .catch(() => {});
        }
      );

      const usernameResponse = await request(app).get('/mbkauthe/db.json?username=support');
      expect(usernameResponse.status).toBe(200);
      expect(usernameResponse.body.queryLog).toHaveLength(1);
      expect(usernameResponse.body.queryLog[0].request.username).toBe('support');

      const urlResponse = await request(app).get('/mbkauthe/db.json?url=/mbkauthe/api/reports');
      expect(urlResponse.status).toBe(200);
      expect(urlResponse.body.queryLog).toHaveLength(1);
      expect(urlResponse.body.queryLog[0].request.url).toBe('/mbkauthe/api/reports');
      expect(urlResponse.body.queryLog[0].trigger.label).toContain('/mbkauthe/api/reports');

      const successResponse = await request(app).get('/mbkauthe/db.json?success=false');
      expect(successResponse.status).toBe(200);
      expect(successResponse.body.queryLog).toHaveLength(1);
      expect(successResponse.body.queryLog[0].success).toBe(false);
      expect(successResponse.body.summary.errorCount).toBe(1);
    });

    test('session-store-shaped queries are labeled as session-store triggers during a request', async () => {
      const fakePool = createFakePool({ name: 'session-db' });

      await runWithRequestContext(
        {
          method: 'GET',
          originalUrl: '/mbkauthe/db.json?limit=50',
          url: '/mbkauthe/db.json?limit=50',
          ip: '127.0.0.1',
          session: {}
        },
        () => fakePool.query({
          text: 'SELECT sess FROM "session" WHERE sid = $1 AND expire >= to_timestamp($2)',
          values: ['abc', 123],
          name: 'sessionLookup'
        })
      );

      const response = await request(app).get('/mbkauthe/db.json?limit=10');

      expect(response.status).toBe(200);
      expect(response.body.queryLog[0].trigger).toMatchObject({
        type: 'request',
        source: 'session-store',
        route: 'GET /mbkauthe/db.json?limit=50'
      });
      expect(response.body.queryLog[0].trigger.label).toContain('Session store during GET /mbkauthe/db.json?limit=50');
    });

    test('POST /mbkauthe/api/login handles login API', async () => {
      const response = await request(app)
        .post('/mbkauthe/api/login')
        .send({ username: 'test', password: 'test' });

      expect([200, 400, 401, 403, 429]).toContain(response.status);
      expect(response.headers['content-type']).toContain('application/json');
    });

    test('POST /mbkauthe/api/login rejects missing credentials', async () => {
      const response = await request(app)
        .post('/mbkauthe/api/login')
        .send({});

      expect(response.status).toBe(400);
      expect(response.headers['content-type']).toContain('application/json');
      expect(response.body).toHaveProperty('errorCode', 1001);
    });

    test('POST /mbkauthe/api/login rejects short passwords before DB auth', async () => {
      const response = await request(app)
        .post('/mbkauthe/api/login')
        .send({ username: 'tester', password: 'short' });

      expect(response.status).toBe(400);
      expect(response.headers['content-type']).toContain('application/json');
      expect(response.body).toHaveProperty('errorCode', 1003);
    });

    test('POST /mbkauthe/api/verify-2fa handles 2FA API', async () => {
      const { csrfToken, cookies } = await getCSRFTokenAndCookies();

      const response = await request(app)
        .post('/mbkauthe/api/verify-2fa')
        .set('Cookie', cookies)
        .send({ token: '123456', _csrf: csrfToken });

      expect([200, 400, 401, 403, 429]).toContain(response.status);
      expect(response.headers['content-type']).toContain('application/json');
    });

    test('POST /mbkauthe/api/verify-2fa rejects malformed tokens', async () => {
      const { csrfToken, cookies } = await getCSRFTokenAndCookies();

      const response = await request(app)
        .post('/mbkauthe/api/verify-2fa')
        .set('Cookie', cookies)
        .send({ token: '12ab', _csrf: csrfToken });

      expect([400, 401]).toContain(response.status);
      expect(response.headers['content-type']).toContain('application/json');
      if (response.status === 400) {
        expect(response.body).toHaveProperty('errorCode', 1004);
      }
    });

    test('POST /mbkauthe/api/terminateAllSessions handles session termination', async () => {
      const { csrfToken, cookies } = await getCSRFTokenAndCookies();

      const response = await request(app)
        .post('/mbkauthe/api/terminateAllSessions')
        .set('Cookie', cookies)
        .send({ _csrf: csrfToken });

      expect([200, 400, 401, 403, 429]).toContain(response.status);

      if (response.status === 401) {
        expect(response.headers['content-type']).not.toContain('application/json');
      } else {
        expect(response.headers['content-type']).toContain('application/json');
      }
    });

    test('GET /mbkauthe/api/checkSession handles session check', async () => {
      const response = await request(app).get('/mbkauthe/api/checkSession');
      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('application/json');
      expect(response.body).toHaveProperty('sessionValid');
    });

    test('POST /mbkauthe/api/checkSession rejects missing session ids', async () => {
      const response = await request(app)
        .post('/mbkauthe/api/checkSession')
        .send({});

      expect(response.status).toBe(400);
      expect(response.headers['content-type']).toContain('application/json');
      expect(response.body).toHaveProperty('errorCode', 1001);
    });

    test('POST /mbkauthe/api/checkSession rejects non-uuid session ids', async () => {
      const response = await request(app)
        .post('/mbkauthe/api/checkSession')
        .send({ sessionId: 'bad-session-id' });

      expect(response.status).toBe(400);
      expect(response.headers['content-type']).toContain('application/json');
      expect(response.body).toHaveProperty('errorCode', 802);
    });

    test('POST /mbkauthe/api/verifySession rejects missing session ids', async () => {
      const response = await request(app)
        .post('/mbkauthe/api/verifySession')
        .send({});

      expect(response.status).toBe(400);
      expect(response.headers['content-type']).toContain('application/json');
      expect(response.body).toHaveProperty('errorCode', 1001);
    });

    test('POST /mbkauthe/api/verifySession rejects invalid encrypted session ids', async () => {
      const response = await request(app)
        .post('/mbkauthe/api/verifySession')
        .send({ sessionId: 'definitely-not-encrypted', isEncrypt: true });

      expect(response.status).toBe(400);
      expect(response.headers['content-type']).toContain('application/json');
      expect(response.body).toHaveProperty('errorCode', 802);
    });

    test('POST /mbkauthe/api/logout handles logout', async () => {
      const response = await request(app).post('/mbkauthe/api/logout').send();
      expect([200, 400, 401, 403, 429]).toContain(response.status);
      if (response.status === 200) {
        expect(response.headers['content-type']).toContain('application/json');
      }
    });

    test('GET /mbkauthe/api/account-sessions handles remembered account listing', async () => {
      const response = await request(app).get('/mbkauthe/api/account-sessions');
      expect([200, 401, 403, 429]).toContain(response.status);
      if (response.status === 200) {
        expect(response.headers['content-type']).toContain('application/json');
        expect(response.body).toHaveProperty('accounts');
      }
    });

    test('GET /mbkauthe/api/account-sessions tolerates malformed remembered-account cookies', async () => {
      const response = await request(app)
        .get('/mbkauthe/api/account-sessions')
        .set('Cookie', ['mbkauthe_accounts=not-json']);

      expect([200, 401, 403, 429]).toContain(response.status);
      if (response.status === 200) {
        expect(Array.isArray(response.body.accounts)).toBe(true);
      }
    });

    test('POST /mbkauthe/api/switch-session rejects invalid session ids', async () => {
      const response = await request(app)
        .post('/mbkauthe/api/switch-session')
        .send({ sessionId: 'not-a-uuid' });

      expect([400, 429]).toContain(response.status);
      expect(response.headers['content-type']).toContain('application/json');
      if (response.status === 400) {
        expect(response.body).toHaveProperty('errorCode');
      }
    });

    test('POST /mbkauthe/api/logout-all handles no-session callers safely', async () => {
      const response = await request(app)
        .post('/mbkauthe/api/logout-all')
        .send({});

      expect([200, 500, 429]).toContain(response.status);
      if (response.status === 200) {
        expect(response.headers['content-type']).toContain('application/json');
        expect(response.body).toHaveProperty('success', true);
      }
    });
  });

  describe('Cross-subdomain cookie sharing', () => {
    test('resolveCookieDomain returns parent domain only when deployed outside test dev', () => {
      expect(resolveCookieDomain('true', 'mbktech.org', true)).toBeUndefined();
      expect(resolveCookieDomain('false', 'mbktech.org', false)).toBeUndefined();
      expect(resolveCookieDomain('true', 'mbktech.org', false)).toBe('.mbktech.org');
      expect(resolveCookieDomain('true', '.mbktech.org', false)).toBe('.mbktech.org');
    });

    test('isAllowedOriginHostname accepts root and nested subdomains', () => {
      expect(isAllowedOriginHostname('mbktech.org', 'mbktech.org')).toBe(true);
      expect(isAllowedOriginHostname('auth.mbktech.org', 'mbktech.org')).toBe(true);
      expect(isAllowedOriginHostname('app.auth.mbktech.org', 'mbktech.org')).toBe(true);
      expect(isAllowedOriginHostname('notmbktech.org', 'mbktech.org')).toBe(false);
      expect(isAllowedOriginHostname('mbktech.org.evil.com', 'mbktech.org')).toBe(false);
    });

    test('cached cookie options omit domain in test dev environment', () => {
      expect(getCookieDomain()).toBeUndefined();
      expect(cachedCookieOptions.domain).toBeUndefined();
      expect(cachedCookieOptions.secure).toBe(false);
    });
  });
});
