import request from 'supertest';

const BASE_URL = "http://localhost:5555";

// Helper to get CSRF token and cookies
const getCSRFTokenAndCookies = async () => {
  const response = await request(BASE_URL).get('/mbkauthe/login');
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
      const response = await request(BASE_URL)
        .get('/login')
        .redirects(0);
      
      expect(response.status).toBe(302);
      expect(response.headers.location).toContain('/mbkauthe/login');
    });

    test('GET /signin redirects to /mbkauthe/login', async () => {
      const response = await request(BASE_URL)
        .get('/signin')
        .redirects(0);
      
      expect(response.status).toBe(302);
      expect(response.headers.location).toContain('/mbkauthe/login');
    });
  });

  describe('Authentication Pages', () => {
    test('GET /mbkauthe/login contains loginUsername input', async () => {
      const response = await request(BASE_URL).get('/mbkauthe/login');
      
      expect(response.status).toBe(200);
      expect(response.text).toMatch(/id\s*=\s*["']loginUsername["']/i);
    });

    test('GET /mbkauthe/2fa contains token input or redirects', async () => {
      const response = await request(BASE_URL)
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
    ])('GET %s contains CurrentVersion div', async (path, desc) => {
      const response = await request(BASE_URL).get(path);
      
      expect(response.status).toBe(200);
      expect(response.text).toMatch(/id\s*=\s*["']CurrentVersion["']/i);
    });

    test('GET /mbkauthe/ErrorCode contains error-603 div', async () => {
      const response = await request(BASE_URL).get('/mbkauthe/ErrorCode');
      
      expect(response.status).toBe(200);
      expect(response.text).toMatch(/id\s*=\s*["']error-603["']/i);
    });
  });

  describe('Static Assets', () => {
    test('GET /mbkauthe/main.js returns JavaScript', async () => {
      const response = await request(BASE_URL).get('/mbkauthe/main.js');
      
      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('javascript');
    });

    test('GET /icon.svg returns SVG content', async () => {
      const response = await request(BASE_URL).get('/icon.svg');
      
      expect(response.status).toBe(200);
      expect(response.text || response.body.toString()).toMatch(/<svg|SVG/);
    });

    test('GET /mbkauthe/bg.webp returns WEBP content', async () => {
      const response = await request(BASE_URL).get('/mbkauthe/bg.webp');
      
      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('image/webp');
    });
  });

  describe('Protected Routes', () => {
    test('GET /mbkauthe/test responds appropriately', async () => {
      const response = await request(BASE_URL).get('/mbkauthe/test');
      expect([200, 302, 401, 403, 429]).toContain(response.status);
    });
  });

  describe('OAuth Routes', () => {
    test('GET /mbkauthe/api/github/login handles GitHub OAuth', async () => {
      const response = await request(BASE_URL)
        .get('/mbkauthe/api/github/login')
        .redirects(0);
      
      expect([200, 302, 403, 500, 429]).toContain(response.status);
      
      if (response.status === 302) {
        const location = response.headers.location;
        expect(location).toMatch(/github\.com|login/);
      }
    });

    test('GET /mbkauthe/api/github/login/callback handles callback', async () => {
      const response = await request(BASE_URL).get('/mbkauthe/api/github/login/callback');
      expect([200, 302, 400, 401, 403, 429]).toContain(response.status);
    });

    test('GET /mbkauthe/api/google/login handles Google OAuth', async () => {
      const response = await request(BASE_URL)
        .get('/mbkauthe/api/google/login')
        .redirects(0);
      
      expect([200, 302, 403, 500, 429]).toContain(response.status);
      
      if (response.status === 302) {
        const location = response.headers.location;
        expect(location).toMatch(/accounts\.google\.com|login/);
      }
    });

    test('GET /mbkauthe/api/google/login/callback handles callback', async () => {
      const response = await request(BASE_URL).get('/mbkauthe/api/google/login/callback');
      expect([200, 302, 400, 401, 403, 429]).toContain(response.status);
    });
  });

  describe('API Endpoints', () => {
    test('POST /mbkauthe/api/login handles login API', async () => {
      const response = await request(BASE_URL)
        .post('/mbkauthe/api/login')
        .send({ username: 'test', password: 'test' });
      
      expect([200, 400, 401, 403, 429]).toContain(response.status);
      expect(response.headers['content-type']).toContain('application/json');
    });

    test('POST /mbkauthe/api/verify-2fa handles 2FA API', async () => {
      const { csrfToken, cookies } = await getCSRFTokenAndCookies();
      
      const response = await request(BASE_URL)
        .post('/mbkauthe/api/verify-2fa')
        .set('Cookie', cookies)
        .send({ token: '123456', _csrf: csrfToken });
      
      expect([200, 400, 401, 403, 429]).toContain(response.status);
      expect(response.headers['content-type']).toContain('application/json');
    });

    test('POST /mbkauthe/api/terminateAllSessions handles session termination', async () => {
      const { csrfToken, cookies } = await getCSRFTokenAndCookies();
      
      const response = await request(BASE_URL)
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
      const response = await request(BASE_URL).get('/mbkauthe/api/checkSession');
      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('application/json');
      expect(response.body).toHaveProperty('sessionValid');
    });

    test('POST /mbkauthe/api/logout handles logout', async () => {
      const response = await request(BASE_URL).post('/mbkauthe/api/logout').send();
      expect([200, 400, 401, 403, 429]).toContain(response.status);
      if (response.status === 200) {
        expect(response.headers['content-type']).toContain('application/json');
      }
    });
  });
});