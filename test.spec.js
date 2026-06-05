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

const { default: router } = await import('./lib/main.js');
const { packageJson } = await import('./lib/config/index.js');
const { dblogin } = await import('./lib/pool.js');

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

describe('mbkauthe Routes', () => {
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
  });

  describe('Static Assets', () => {
    test('GET /mbkauthe/main.js returns JavaScript', async () => {
      const response = await request(app).get('/mbkauthe/main.js');

      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('javascript');
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
});
