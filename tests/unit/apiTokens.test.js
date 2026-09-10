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

const { SqlitePool } = await import('../../lib/db/sqlitePool.js');
const { sqliteDialect } = await import('../../lib/db/dialects/sqlite.js');
const { ApiTokenRepository } = await import('../../lib/db/ApiTokenRepository.js');

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
    `INSERT INTO mbkcore_users (username, password_hash, role, is_active)
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

    test('returns tokens ordered by CreatedAt desc', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert('tokentest', 'Token A', 'hash_a', 'mbk_a', { permissions: [] }, null);
      await repo.insert('tokentest', 'Token B', 'hash_b', 'mbk_b', { permissions: ['portal:posts:view'] }, '2099-01-01');
      // Force Token A to be older so ordering is deterministic (same-millisecond inserts can tie).
      await pool.query(`UPDATE mbkcore_api_tokens SET created_at = '2020-01-01 00:00:00' WHERE token_hash = ?`, ['hash_a']);

      const rows = await repo.listForUser('tokentest');
      expect(rows).toHaveLength(2);
      expect(rows[0].name).toBe('Token B'); // newest first
      expect(rows[0].token_permissions).toEqual(['portal:posts:view']);
      expect(rows[1].name).toBe('Token A');
      expect(rows[1].token_permissions).toEqual([]);
    });
  });

  describe('countForUser', () => {
    test('returns 0 for user with no tokens', async () => {
      await insertUser(pool, { username: 'tokentest' });
      expect(await repo.countForUser('tokentest')).toBe(0);
    });

    test('counts tokens correctly', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert('tokentest', 'T1', 'h1', 'p1', { permissions: [] }, null);
      await repo.insert('tokentest', 'T2', 'h2', 'p2', { permissions: [] }, null);
      expect(await repo.countForUser('tokentest')).toBe(2);
    });
  });

  describe('insert', () => {
    test('inserts a token and returns it with its permissions', async () => {
      await insertUser(pool, { username: 'tokentest' });
      const token = await repo.insert('tokentest', 'My Token', 'hash123', 'mbk_', { permissions: ['portal:posts:create'] }, '2099-12-31');

      expect(token.id).toBeGreaterThan(0);
      expect(token.name).toBe('My Token');
      expect(token.prefix).toBe('mbk_');
      expect(token.token_permissions).toEqual(['portal:posts:create']);
    });

    test('accepts a JSON-string permissions value', async () => {
      await insertUser(pool, { username: 'tokentest' });
      const token = await repo.insert('tokentest', 'Str', 'hash_s', 'mbk_', JSON.stringify({ permissions: ['portal:posts:create'] }), null);
      expect(token.token_permissions).toEqual(['portal:posts:create']);
    });
  });

  describe('deleteByIdAndUsername', () => {
    test('deletes only tokens owned by the user', async () => {
      await insertUser(pool, { username: 'owner' });
      await insertUser(pool, { username: 'other' });
      const inserted = await repo.insert('owner', 'Owned', 'h1', 'mbk_', { permissions: [] }, null);
      await repo.insert('other', 'Other', 'h2', 'mbk_', { permissions: [] }, null);

      const result = await repo.deleteByIdAndUsername(inserted.id, 'owner');
      expect(result.rowCount).toBe(1);
      expect(result.rows[0].name).toBe('Owned');

      const remaining = await repo.listAll();
      expect(remaining).toHaveLength(1);
      expect(remaining[0].name).toBe('Other');
    });

    test('rowCount is 0 when the token is not owned by the user', async () => {
      await insertUser(pool, { username: 'owner' });
      const inserted = await repo.insert('owner', 'Owned', 'h1', 'mbk_', { permissions: [] }, null);
      const result = await repo.deleteByIdAndUsername(inserted.id, 'nobody');
      expect(result.rowCount).toBe(0);
    });
  });

  describe('findByTokenHash', () => {
    test('finds a token by hash', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert('tokentest', 'FindMe', 'unique_hash_42', 'mbk_x', { permissions: [] }, null);

      const found = await repo.findByTokenHash('unique_hash_42');
      expect(found).toHaveLength(1);
      expect(found[0].username).toBe('tokentest');
    });

    test('returns empty array for unknown hash', async () => {
      await insertUser(pool, { username: 'tokentest' });
      expect(await repo.findByTokenHash('nonexistent')).toEqual([]);
    });
  });

  describe('updateLastUsedByHash', () => {
    test('updates the LastUsed timestamp', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert('tokentest', 'T', 'hash_last', 'mbk_', { permissions: [] }, null);

      const res = await repo.updateLastUsedByHash('hash_last');
      expect(res.rowCount).toBe(1);

      const rows = await repo.findByTokenHash('hash_last');
      expect(rows[0].last_used).toBeTruthy();
    });
  });

  describe('admin queries', () => {
    test('listAll returns tokens with user info', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert('tokentest', 'A', 'ha', 'mbk_', { permissions: [] }, null);

      const rows = await repo.listAll();
      expect(rows).toHaveLength(1);
      expect(rows[0].username).toBe('tokentest');
      expect(rows[0].token_permissions).toEqual([]);
      expect(rows[0].role).toBe('normaluser');
    });

    test('stats returns aggregate numbers', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert('tokentest', 'A', 'ha', 'mbk_', { permissions: [] }, null);
      await repo.insert('tokentest', 'B', 'hb', 'mbk_', { permissions: ['portal:posts:view'] }, '2099-01-01');

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
      await repo.insert('u1', 'A', 'ha', 'mbk_', { permissions: [] }, null);
      await repo.insert('u2', 'B', 'hb', 'mbk_', { permissions: [] }, null);

      const rows = await repo.listForUserAdmin('u2');
      expect(rows).toHaveLength(1);
      expect(rows[0].name).toBe('B');
    });

    test('findInfoById / deleteById / deleteAllByUsername', async () => {
      await insertUser(pool, { username: 'tokentest' });
      const inserted = await repo.insert('tokentest', 'A', 'ha', 'mbk_', { permissions: [] }, null);

      const info = await repo.findInfoById(inserted.id);
      expect(info.username).toBe('tokentest');
      expect(info.name).toBe('A');

      await repo.deleteById(inserted.id);
      expect(await repo.countForUser('tokentest')).toBe(0);

      await repo.insert('tokentest', 'B', 'hb', 'mbk_', { permissions: [] }, null);
      await repo.insert('tokentest', 'C', 'hc', 'mbk_', { permissions: [] }, null);
      await repo.deleteAllByUsername('tokentest');
      expect(await repo.countForUser('tokentest')).toBe(0);
    });
  });

  describe('listForUserDetail', () => {
    test('returns detail rows with formatted dates, is_active and Permissions', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert('tokentest', 'A', 'ha', 'mbk_', { permissions: ['portal:posts:view'] }, '2099-01-01');

      const rows = await repo.listForUserDetail('tokentest');
      expect(rows).toHaveLength(1);
      expect(rows[0].name).toBe('A');
      expect(rows[0].token_permissions).toEqual(['portal:posts:view']);
      expect(rows[0].formatted_created).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
      expect(rows[0].is_active).toBe(true);
    });

    test('expired token is not active', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert('tokentest', 'Old', 'ho', 'mbk_', { permissions: [] }, null);
      // Schema requires ExpiresAt > CreatedAt, so backdate both into the past.
      await pool.query(`UPDATE mbkcore_api_tokens SET created_at = '2019-01-01 00:00:00', expires_at = '2020-01-01 00:00:00' WHERE token_hash = ?`, ['ho']);

      const rows = await repo.listForUserDetail('tokentest');
      expect(rows[0].is_active).toBe(false);
    });
  });

  describe('token permission list', () => {
    test('round-trips an explicit permission allow-list', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert(
        'tokentest',
        'Scoped',
        'hash_scoped',
        'mbk_',
        { permissions: ['portal:dns:view', 'portal:procurement:view'] },
        null
      );

      const rows = await repo.listForUser('tokentest');
      expect(rows[0].token_permissions).toEqual(['portal:dns:view', 'portal:procurement:view']);

      const detail = await repo.listForUserDetail('tokentest');
      expect(detail[0].token_permissions).toEqual(['portal:dns:view', 'portal:procurement:view']);
    });

    test('legacy tokens (no permission list) expose an empty list', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert('tokentest', 'Legacy', 'hash_legacy', 'mbk_', { permissions: [] }, null);

      const rows = await repo.listForUser('tokentest');
      expect(rows[0].token_permissions).toEqual([]);
    });

    test('normalizes stored permission casing and skips empty entries', async () => {
      await insertUser(pool, { username: 'tokentest' });
      await repo.insert(
        'tokentest',
        'Mixed',
        'hash_mixed',
        'mbk_',
        JSON.stringify({ permissions: ['Portal:DNS:View', '', 'portal:dns:delete'] }),
        null
      );

      const rows = await repo.listForUser('tokentest');
      expect(rows[0].token_permissions).toEqual(['portal:dns:view', 'portal:dns:delete']);
    });
  });
});
