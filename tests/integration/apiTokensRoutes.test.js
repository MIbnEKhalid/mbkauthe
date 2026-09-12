// Route tests for the API token management router (verify endpoint, no session needed).
import request from 'supertest';
import express from 'express';
import { readFile } from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

process.env.test = 'dev';
process.env.env = 'dev';
process.env.mbkautheVar = JSON.stringify({
  APP_NAME: 'mbkauthe',
  MAIN_SECRET_TOKEN: 'api-routes-main-secret-token',
  SESSION_SECRET_KEY: 'api-routes-session-secret-key',
  IS_DEPLOYED: 'false',
  DOMAIN: 'localhost',
  DB_TYPE: 'sqlite',
  SQLITE_PATH: ':memory:',
  MBKAUTH_TWO_FA_ENABLE: 'false',
  COOKIE_EXPIRE_TIME: 2,
  MAX_SESSIONS_PER_USER: 5
});

const { dblogin } = await import('../../lib/pool.js');
const { sqliteDialect } = await import('../../lib/db/dialects/sqlite.js');
const { ApiTokenRepository } = await import('../../lib/repositories/ApiTokenRepository.js');
const { hashApiToken, generatePrefixedToken } = await import('../../lib/config/security.js');
const { default: apiTokensRouter } = await import('../../lib/routes/apiTokens.js');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = path.join(__dirname, '../../docs/schema/db.sqlite.sql');

const schemaSql = await readFile(SCHEMA_PATH, 'utf8');
dblogin.execScript(schemaSql);

const repo = new ApiTokenRepository({ db: dblogin, dialect: sqliteDialect });

async function insertUser(username, { role = 'normaluser', active = 1 } = {}) {
  await dblogin.query(
    `INSERT INTO mbkcore_users (username, password_hash, role, is_active)
     VALUES (?, ?, ?, ?)`,
    [username, 'test-hash', role, active]
  );
}

const app = express();
app.use(express.json());
app.use(apiTokensRouter);

describe('POST /api/tokens/verify', () => {
  test('returns valid with username and permissions for a real token', async () => {
    await insertUser('verify-ok');
    const raw = generatePrefixedToken();
    await repo.insert('verify-ok', 'V', hashApiToken(raw), raw.substring(0, 8), JSON.stringify({ permissions: ['portal:dns:view'] }), null);

    const res = await request(app).post('/api/tokens/verify').set('Authorization', `Bearer ${raw}`);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.username).toBe('verify-ok');
    expect(res.body.permissions).toEqual(['portal:dns:view']);
  });

  test('returns the token permission list (empty for legacy tokens)', async () => {
    await insertUser('verify-perms');
    const raw = generatePrefixedToken();
    await repo.insert(
      'verify-perms',
      'P',
      hashApiToken(raw),
      raw.substring(0, 8),
      JSON.stringify({ permissions: ['portal:dns:view'] }),
      null
    );

    const res = await request(app).post('/api/tokens/verify').set('Authorization', `Bearer ${raw}`);
    expect(res.status).toBe(200);
    expect(res.body.permissions).toEqual(['portal:dns:view']);
  });

  test('rejects a request with no token', async () => {
    const res = await request(app).post('/api/tokens/verify');
    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  test('rejects an unknown token', async () => {
    const res = await request(app).post('/api/tokens/verify').set('Authorization', 'Bearer not-a-real-token');
    expect(res.status).toBe(401);
    expect(res.body.message).toBe('Invalid token');
  });

  test('rejects an expired token', async () => {
    await insertUser('verify-expired');
    const raw = generatePrefixedToken();
    await repo.insert('verify-expired', 'E', hashApiToken(raw), raw.substring(0, 8), JSON.stringify({ permissions: [] }), null);
    // Schema requires expires_at > created_at, so backdate both into the past.
    await dblogin.query(`UPDATE mbkcore_api_tokens SET created_at = '2019-01-01 00:00:00', expires_at = '2020-01-01 00:00:00' WHERE token_hash = ?`, [hashApiToken(raw)]);

    const res = await request(app).post('/api/tokens/verify').set('Authorization', `Bearer ${raw}`);
    expect(res.status).toBe(401);
    expect(res.body.message).toBe('Token expired');
  });

  test('updates LastUsed after a successful verification', async () => {
    await insertUser('verify-touch');
    const raw = generatePrefixedToken();
    await repo.insert('verify-touch', 'V2', hashApiToken(raw), raw.substring(0, 8), JSON.stringify({ permissions: [] }), null);

    await request(app).post('/api/tokens/verify').set('Authorization', `Bearer ${raw}`);
    const rows = await repo.findByTokenHash(hashApiToken(raw));
    expect(rows[0].last_used).toBeTruthy();
  });
});
