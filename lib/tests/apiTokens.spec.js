// Unit tests for ApiTokenRepository (SQLite backend).
import { readFile } from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

process.env.test = 'dev';
process.env.env = 'dev';
process.env.mbkautheVar = JSON.stringify({
  APP_NAME: 'mbkauthe',
  MAIN_SECRET_TOKEN: 'api-tokens-main-secret-token',
  SESSION_SECRET_KEY: 'api-tokens-session-secret-key',
  IS_DEPLOYED: 'false',
  DOMAIN: 'localhost',
  DB_TYPE: 'sqlite',
  SQLITE_PATH: ':memory:',
  MBKAUTH_TWO_FA_ENABLE: 'false',
  COOKIE_EXPIRE_TIME: 2,
  MAX_SESSIONS_PER_USER: 5
});

const { SqlitePool } = await import('../db/sqlitePool.js');
const { sqliteDialect } = await import('../db/dialects/sqlite.js');
const { ApiTokenRepository } = await import('../db/ApiTokenRepository.js');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = path.join(__dirname, '../../docs/schema/db.sqlite.sql');

let schemaSql;

beforeAll(async () => {
  schemaSql = await readFile(SCHEMA_PATH, 'utf8');
});

/** Fresh in-memory database with the real schema applied. */
function createPool() {
  const pool = new SqlitePool(':memory:');
  pool.execScript(schemaSql);
  return pool;
}

async function insertUser(pool, { username, role = 'normaluser', active = 1 } = {}) {
  await pool.query(
    `INSERT INTO users (username, password_hash, role, is_active)
     VALUES (?, ?, ?, ?)`,
    [username, 'test-hash', role, active]
  );
}

describe('ApiTokenRepository', () => {
  let pool, repo;

  beforeEach(async () => {
    pool = createPool();
    repo = new ApiTokenRepository({ db: pool, dialect: sqliteDialect });
  });

  describe('listForUser', () => {
    test('returns empty array for user with no tokens', async () => {
      await insertUser(pool, { username: 'tokentest' });
      const rows = await repo.listForUser('tokentest');
      expect(rows).toEqual([]);
    });

    test('returns tokens ordered by CreatedAt desc with Scope/AllowedApps', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert('tokentest', 'Token A', 'hash_a', 'mbk_a', { scope: 'read-only', allowed_apps: null }, null);
      await repo.insert('tokentest', 'Token B', 'hash_b', 'mbk_b', { scope: 'write', allowed_apps: ['Portal'] }, '2099-01-01');
      // Force Token A to be older so ordering is deterministic (same-millisecond inserts can tie).
      await pool.query(`UPDATE api_tokens SET created_at = '2020-01-01 00:00:00' WHERE token_hash = ?`, ['hash_a']);

      const rows = await repo.listForUser('tokentest');
      expect(rows).toHaveLength(2);
      expect(rows[0].name).toBe('Token B'); // newest first
      expect(rows[0].scope).toBe('write');
      expect(rows[0].allowed_apps).toEqual(['Portal']);
      expect(rows[1].name).toBe('Token A');
      expect(rows[1].scope).toBe('read-only');
      expect(rows[1].allowed_apps).toBeNull();
    });
  });

  describe('countForUser', () => {
    test('returns 0 for user with no tokens', async () => {
      await insertUser(pool, { username: 'tokentest' });
      expect(await repo.countForUser('tokentest')).toBe(0);
    });

    test('counts tokens correctly', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert('tokentest', 'T1', 'h1', 'p1', { scope: 'read-only', allowed_apps: null }, null);
      await repo.insert('tokentest', 'T2', 'h2', 'p2', { scope: 'read-only', allowed_apps: null }, null);
      expect(await repo.countForUser('tokentest')).toBe(2);
    });
  });

  describe('insert', () => {
    test('inserts a token and returns it with Scope/AllowedApps', async () => {
      await insertUser(pool, { username: 'tokentest' });
      const token = await repo.insert('tokentest', 'My Token', 'hash123', 'mbk_', { scope: 'read-only', allowed_apps: ['Portal'] }, '2099-12-31');

      expect(token.id).toBeGreaterThan(0);
      expect(token.name).toBe('My Token');
      expect(token.prefix).toBe('mbk_');
      expect(token.scope).toBe('read-only');
      expect(token.allowed_apps).toEqual(['Portal']);
    });

    test('accepts a JSON-string permissions value', async () => {
      await insertUser(pool, { username: 'tokentest' });
      const token = await repo.insert('tokentest', 'Str', 'hash_s', 'mbk_', JSON.stringify({ scope: 'write', allowed_apps: null }), null);
      expect(token.scope).toBe('write');
      expect(token.allowed_apps).toBeNull();
    });
  });

  describe('deleteByIdAndUsername', () => {
    test('deletes only tokens owned by the user', async () => {
      await insertUser(pool, { username: 'owner' });
      await insertUser(pool, { username: 'other' });
      const inserted = await repo.insert('owner', 'Owned', 'h1', 'mbk_', { scope: 'read-only', allowed_apps: null }, null);
      await repo.insert('other', 'Other', 'h2', 'mbk_', { scope: 'read-only', allowed_apps: null }, null);

      const result = await repo.deleteByIdAndUsername(inserted.id, 'owner');
      expect(result.rowCount).toBe(1);
      expect(result.rows[0].name).toBe('Owned');

      const remaining = await repo.listAll();
      expect(remaining).toHaveLength(1);
      expect(remaining[0].name).toBe('Other');
    });

    test('rowCount is 0 when the token is not owned by the user', async () => {
      await insertUser(pool, { username: 'owner' });
      const inserted = await repo.insert('owner', 'Owned', 'h1', 'mbk_', { scope: 'read-only', allowed_apps: null }, null);
      const result = await repo.deleteByIdAndUsername(inserted.id, 'nobody');
      expect(result.rowCount).toBe(0);
    });
  });

  describe('findByTokenHash', () => {
    test('finds a token by hash with Scope/AllowedApps', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert('tokentest', 'FindMe', 'unique_hash_42', 'mbk_x', { scope: 'write', allowed_apps: null }, null);

      const found = await repo.findByTokenHash('unique_hash_42');
      expect(found).toHaveLength(1);
      expect(found[0].username).toBe('tokentest');
      expect(found[0].scope).toBe('write');
    });

    test('returns empty array for unknown hash', async () => {
      await insertUser(pool, { username: 'tokentest' });
      expect(await repo.findByTokenHash('nonexistent')).toEqual([]);
    });
  });

  describe('updateLastUsedByHash', () => {
    test('updates the LastUsed timestamp', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert('tokentest', 'T', 'hash_last', 'mbk_', { scope: 'read-only', allowed_apps: null }, null);

      const res = await repo.updateLastUsedByHash('hash_last');
      expect(res.rowCount).toBe(1);

      const rows = await repo.findByTokenHash('hash_last');
      expect(rows[0].last_used).toBeTruthy();
    });
  });

  describe('admin queries', () => {
    test('listAll returns tokens with user info', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert('tokentest', 'A', 'ha', 'mbk_', { scope: 'read-only', allowed_apps: null }, null);

      const rows = await repo.listAll();
      expect(rows).toHaveLength(1);
      expect(rows[0].username).toBe('tokentest');
      expect(rows[0].scope).toBe('read-only');
      expect(rows[0].role).toBe('normaluser');
    });

    test('stats returns aggregate numbers', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert('tokentest', 'A', 'ha', 'mbk_', { scope: 'read-only', allowed_apps: null }, null);
      await repo.insert('tokentest', 'B', 'hb', 'mbk_', { scope: 'write', allowed_apps: null }, '2099-01-01');

      const stats = await repo.stats();
      expect(Number(stats.total_tokens)).toBe(2);
      expect(Number(stats.users_with_tokens)).toBe(1);
      expect(Number(stats.never_expire)).toBe(1);
      expect(Number(stats.active_with_expiry)).toBe(1);
      expect(Number(stats.never_used)).toBe(2);
    });

    test('listForUserAdmin returns tokens for a specific user', async () => {
      await insertUser(pool, { username: 'u1' });
      await insertUser(pool, { username: 'u2' });
      await repo.insert('u1', 'A', 'ha', 'mbk_', { scope: 'read-only', allowed_apps: null }, null);
      await repo.insert('u2', 'B', 'hb', 'mbk_', { scope: 'read-only', allowed_apps: null }, null);

      const rows = await repo.listForUserAdmin('u2');
      expect(rows).toHaveLength(1);
      expect(rows[0].name).toBe('B');
    });

    test('findInfoById / deleteById / deleteAllByUsername', async () => {
      await insertUser(pool, { username: 'tokentest' });
      const inserted = await repo.insert('tokentest', 'A', 'ha', 'mbk_', { scope: 'read-only', allowed_apps: null }, null);

      const info = await repo.findInfoById(inserted.id);
      expect(info.username).toBe('tokentest');
      expect(info.name).toBe('A');

      await repo.deleteById(inserted.id);
      expect(await repo.countForUser('tokentest')).toBe(0);

      await repo.insert('tokentest', 'B', 'hb', 'mbk_', { scope: 'read-only', allowed_apps: null }, null);
      await repo.insert('tokentest', 'C', 'hc', 'mbk_', { scope: 'read-only', allowed_apps: null }, null);
      await repo.deleteAllByUsername('tokentest');
      expect(await repo.countForUser('tokentest')).toBe(0);
    });
  });

  describe('listForUserDetail', () => {
    test('returns detail rows with formatted dates, is_active and Permissions', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert('tokentest', 'A', 'ha', 'mbk_', { scope: 'read-only', allowed_apps: ['Portal'] }, '2099-01-01');

      const rows = await repo.listForUserDetail('tokentest');
      expect(rows).toHaveLength(1);
      expect(rows[0].name).toBe('A');
      expect(rows[0].permissions.scope).toBe('read-only');
      expect(rows[0].formatted_created).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
      expect(rows[0].is_active).toBe(true);
    });

    test('expired token is not active', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert('tokentest', 'Old', 'ho', 'mbk_', { scope: 'read-only', allowed_apps: null }, null);
      // Schema requires ExpiresAt > CreatedAt, so backdate both into the past.
      await pool.query(`UPDATE api_tokens SET created_at = '2019-01-01 00:00:00', expires_at = '2020-01-01 00:00:00' WHERE token_hash = ?`, ['ho']);

      const rows = await repo.listForUserDetail('tokentest');
      expect(rows[0].is_active).toBe(false);
    });
  });
});
