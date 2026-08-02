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
  Main_SECRET_TOKEN: 'api-routes-main-secret-token',
  SESSION_SECRET_KEY: 'api-routes-session-secret-key',
  IS_DEPLOYED: 'false',
  DOMAIN: 'localhost',
  DB_TYPE: 'sqlite',
  SQLITE_PATH: ':memory:',
  MBKAUTH_TWO_FA_ENABLE: 'false',
  COOKIE_EXPIRE_TIME: 2,
  MAX_SESSIONS_PER_USER: 5
});

const { dblogin } = await import('../pool.js');
const { sqliteDialect } = await import('../db/dialects/sqlite.js');
const { ApiTokenRepository } = await import('../db/ApiTokenRepository.js');
const { hashApiToken, generatePrefixedToken } = await import('../config/security.js');
const { default: apiTokensRouter } = await import('../routes/apiTokens.js');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = path.join(__dirname, '../../docs/schema/db.sqlite.sql');

const schemaSql = await readFile(SCHEMA_PATH, 'utf8');
dblogin.execScript(schemaSql);

const repo = new ApiTokenRepository({ db: dblogin, dialect: sqliteDialect });

async function insertUser(username, { role = 'NormalUser', active = 1 } = {}) {
  await dblogin.query(
    `INSERT INTO "Users" ("UserName", "PasswordEnc", "Role", "Active")
     VALUES (?, ?, ?, ?)`,
    [username, 'test-hash', role, active]
  );
}

const app = express();
app.use(express.json());
app.use(apiTokensRouter);

describe('POST /api/tokens/verify', () => {
  test('returns valid with username/scope/allowedApps for a real token', async () => {
    await insertUser('verify-ok');
    const raw = generatePrefixedToken();
    await repo.insert('verify-ok', 'V', hashApiToken(raw), raw.substring(0, 8), JSON.stringify({ scope: 'read-only', allowedApps: ['Portal'] }), null);

    const res = await request(app).post('/api/tokens/verify').set('Authorization', `Bearer ${raw}`);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.username).toBe('verify-ok');
    expect(res.body.scope).toBe('read-only');
    expect(res.body.allowedApps).toEqual(['Portal']);
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
    await repo.insert('verify-expired', 'E', hashApiToken(raw), raw.substring(0, 8), JSON.stringify({ scope: 'read-only', allowedApps: null }), null);
    // Schema requires ExpiresAt > CreatedAt, so backdate both into the past.
    await dblogin.query(`UPDATE "ApiTokens" SET "CreatedAt" = '2019-01-01 00:00:00', "ExpiresAt" = '2020-01-01 00:00:00' WHERE "TokenHash" = ?`, [hashApiToken(raw)]);

    const res = await request(app).post('/api/tokens/verify').set('Authorization', `Bearer ${raw}`);
    expect(res.status).toBe(401);
    expect(res.body.message).toBe('Token expired');
  });

  test('updates LastUsed after a successful verification', async () => {
    await insertUser('verify-touch');
    const raw = generatePrefixedToken();
    await repo.insert('verify-touch', 'V2', hashApiToken(raw), raw.substring(0, 8), JSON.stringify({ scope: 'read-only', allowedApps: null }), null);

    await request(app).post('/api/tokens/verify').set('Authorization', `Bearer ${raw}`);
    const rows = await repo.findByTokenHash(hashApiToken(raw));
    expect(rows[0].LastUsed).toBeTruthy();
  });
});
