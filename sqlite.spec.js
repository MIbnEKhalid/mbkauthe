import { readFile } from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

import { SqlitePool } from './lib/db/sqlitePool.js';
import { translatePgToSqlite } from './lib/db/sqlSqliteTranslate.js';
import { SqliteSessionStore } from './lib/session/SqliteSessionStore.js';
import { sqliteDialect } from './lib/db/dialects/sqlite.js';
import { AuthRepository } from './lib/db/AuthRepository.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = path.join(__dirname, 'docs/schema/db.sqlite.sql');

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

async function insertUser(pool, { username, role = 'NormalUser', active = 1, allowedApps } = {}) {
  const columns = ['"UserName"', '"PasswordEnc"', '"Role"', '"Active"'];
  const values = [username, 'test-hash', role, active];
  if (allowedApps !== undefined) {
    columns.push('"AllowedApps"');
    values.push(JSON.stringify(allowedApps));
  }
  await pool.query(
    `INSERT INTO "Users" (${columns.join(', ')}) VALUES (${columns.map(() => '?').join(', ')})`,
    values
  );
}

describe('translatePgToSqlite', () => {
  test('passes native ?-placeholder queries through with values intact', () => {
    const { text, values } = translatePgToSqlite(
      'SELECT sess FROM "session" WHERE sid = ?',
      ['abc']
    );
    expect(text).toBe('SELECT sess FROM "session" WHERE sid = ?');
    expect(values).toEqual(['abc']);
  });

  test('rewrites $N placeholders to ? preserving order', () => {
    const { text, values } = translatePgToSqlite(
      'SELECT * FROM "Users" WHERE "UserName" = $1 AND "Role" = $2',
      ['support', 'SuperAdmin']
    );
    expect(text).toBe('SELECT * FROM "Users" WHERE "UserName" = ? AND "Role" = ?');
    expect(values).toEqual(['support', 'SuperAdmin']);
  });

  test('handles repeated $N references by duplicating the value', () => {
    const { text, values } = translatePgToSqlite(
      'SELECT * FROM t WHERE a = $1 OR b = $1',
      ['x']
    );
    expect(text).toBe('SELECT * FROM t WHERE a = ? OR b = ?');
    expect(values).toEqual(['x', 'x']);
  });

  test('expands = ANY($1) with an array into IN (?, ?, ...)', () => {
    const { text, values } = translatePgToSqlite(
      'DELETE FROM "Sessions" WHERE id = ANY($1)',
      [['a', 'b', 'c']]
    );
    expect(text).toBe('DELETE FROM "Sessions" WHERE id IN (?, ?, ?)');
    expect(values).toEqual(['a', 'b', 'c']);
  });

  test('expands = ANY($1) with an empty array into IN (NULL)', () => {
    const { text, values } = translatePgToSqlite(
      'DELETE FROM "Sessions" WHERE id = ANY($1)',
      [[]]
    );
    expect(text).toBe('DELETE FROM "Sessions" WHERE id IN (NULL)');
    expect(values).toEqual([]);
  });

  test('converts NOW(), TRUE/FALSE literals, and strips ::type casts', () => {
    const { text } = translatePgToSqlite(
      'SELECT COUNT(*)::int AS c FROM t WHERE ok = TRUE AND bad = FALSE AND ts <= NOW()',
      []
    );
    expect(text).toBe(
      'SELECT COUNT(*) AS c FROM t WHERE ok = 1 AND bad = 0 AND ts <= CURRENT_TIMESTAMP'
    );
  });
});

describe('SqlitePool bind-value coercion', () => {
  let pool;

  beforeEach(() => {
    pool = createPool();
  });

  afterEach(async () => {
    await pool.end();
  });

  test('binds Date values as UTC CURRENT_TIMESTAMP-format text', async () => {
    await insertUser(pool, { username: 'u1' });
    const expiresAt = new Date('2030-01-02T03:04:05.678Z');
    await pool.query({
      text: 'INSERT INTO "Sessions" ("UserName", expires_at) VALUES ($1, $2)',
      values: ['u1', expiresAt]
    });

    // Read the raw stored text via a column normalizeRow does not touch.
    const raw = await pool.query(
      'SELECT CAST(expires_at AS TEXT) AS raw_expires FROM "Sessions"'
    );
    expect(raw.rows[0].raw_expires).toBe('2030-01-02 03:04:05');
  });

  test('binds booleans as 1/0 and undefined as null', async () => {
    await insertUser(pool, { username: 'u1' });
    await pool.query({
      text: 'UPDATE "Users" SET "Active" = $1, "FullName" = $2 WHERE "UserName" = $3',
      values: [false, undefined, 'u1']
    });
    const row = (await pool.query('SELECT "Active", "FullName" FROM "Users" WHERE "UserName" = ?', ['u1'])).rows[0];
    expect(row.Active).toBe(0);
    expect(row.FullName).toBeNull();
  });

  test('serializes plain objects and arrays to JSON like the pg driver', async () => {
    await insertUser(pool, { username: 'u1' });
    const meta = { ip: '::1', nested: { depth: 2 } };
    const inserted = await pool.query({
      text: 'INSERT INTO "Sessions" ("UserName", meta) VALUES ($1, $2) RETURNING id',
      values: ['u1', meta]
    });
    const row = (await pool.query({
      text: 'SELECT meta FROM "Sessions" WHERE id = $1',
      values: [inserted.rows[0].id]
    })).rows[0];
    expect(row.meta).toEqual(meta);
  });
});

describe('SqlitePool row normalization (pg result-shape parity)', () => {
  let pool;

  beforeEach(() => {
    pool = createPool();
  });

  afterEach(async () => {
    await pool.end();
  });

  test('returns JSON columns as parsed values, not strings', async () => {
    await insertUser(pool, { username: 'u1', allowedApps: ['Portal', 'mbkauthe'] });
    const row = (await pool.query({
      text: 'SELECT "AllowedApps", "Positions", "SocialAccounts" FROM "Users" WHERE "UserName" = $1',
      values: ['u1']
    })).rows[0];

    expect(Array.isArray(row.AllowedApps)).toBe(true);
    expect(row.AllowedApps).toEqual(['Portal', 'mbkauthe']);
    expect(typeof row.Positions).toBe('object');
    expect(typeof row.SocialAccounts).toBe('object');
  });

  test('parses aliased JSON column user_allowed_apps (getApiTokenByHash shape)', async () => {
    await insertUser(pool, { username: 'u1' });
    await pool.query({
      text: 'INSERT INTO "ApiTokens" ("UserName", "Name", "TokenHash", "Prefix") VALUES ($1, $2, $3, $4)',
      values: ['u1', 'token', 'hash-1', 'mbk_']
    });
    const row = (await pool.query({
      text: `SELECT t."Permissions", u."AllowedApps" AS user_allowed_apps
             FROM "ApiTokens" t JOIN "Users" u ON t."UserName" = u."UserName"
             WHERE t."TokenHash" = $1`,
      values: ['hash-1']
    })).rows[0];

    expect(row.Permissions).toEqual({ scope: 'read-only', allowedApps: null });
    expect(Array.isArray(row.user_allowed_apps)).toBe(true);
  });

  test('returns timestamp columns as UTC Date objects without timezone shift', async () => {
    await insertUser(pool, { username: 'u1' });
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
    await pool.query({
      text: 'INSERT INTO "Sessions" ("UserName", expires_at) VALUES ($1, $2)',
      values: ['u1', expiresAt]
    });
    const row = (await pool.query('SELECT expires_at, created_at FROM "Sessions"')).rows[0];

    expect(row.expires_at).toBeInstanceOf(Date);
    expect(row.created_at).toBeInstanceOf(Date);
    // Storage truncates milliseconds; anything beyond that indicates the
    // local-time parsing bug (offset would be whole minutes/hours).
    expect(Math.abs(row.expires_at.getTime() - expiresAt.getTime())).toBeLessThan(1000);
    expect(Math.abs(row.created_at.getTime() - Date.now())).toBeLessThan(5000);
  });

  test('leaves session-store columns sess and expire as raw strings', async () => {
    await pool.query(
      'INSERT INTO "session" (sid, sess, expire) VALUES (?, ?, ?)',
      ['sid-1', '{"cookie":{}}', '2030-01-01 00:00:00']
    );
    const row = (await pool.query('SELECT sess, expire FROM "session" WHERE sid = ?', ['sid-1'])).rows[0];
    expect(typeof row.sess).toBe('string');
    expect(typeof row.expire).toBe('string');
  });

  test('leaves non-JSON text that happens to sit in a JSON column intact on parse failure', async () => {
    await pool.query('INSERT INTO "Users" ("UserName", "AllowedApps") VALUES (?, ?)', ['u1', 'not-json']);
    const row = (await pool.query('SELECT "AllowedApps" FROM "Users" WHERE "UserName" = ?', ['u1'])).rows[0];
    expect(row.AllowedApps).toBe('not-json');
  });
});

describe('SqlitePool transaction mutex', () => {
  let pool;

  beforeEach(() => {
    pool = createPool();
    pool.execScript('CREATE TABLE t (id INTEGER PRIMARY KEY, who TEXT)');
  });

  afterEach(async () => {
    await pool.end();
  });

  async function runTx(who, { fail = false, delayMs = 10 } = {}) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('INSERT INTO t (who) VALUES ($1)', [who]);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      await client.query('INSERT INTO t (who) VALUES ($1)', [`${who}-2`]);
      if (fail) throw new Error('boom');
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      if (err.message !== 'boom') throw err;
    } finally {
      client.release();
    }
  }

  test('concurrent transactions do not nest or corrupt each other', async () => {
    await Promise.all([runTx('alice'), runTx('bob'), runTx('carol')]);
    const rows = (await pool.query('SELECT who FROM t ORDER BY id')).rows.map((r) => r.who);
    expect(rows).toHaveLength(6);
    for (const who of ['alice', 'bob', 'carol']) {
      expect(rows).toContain(who);
      expect(rows).toContain(`${who}-2`);
    }
  });

  test('a rolled-back transaction does not take bystander pool queries with it', async () => {
    await Promise.all([
      runTx('good'),
      runTx('bad', { fail: true }),
      pool.query('INSERT INTO t (who) VALUES (?)', ['bystander'])
    ]);
    const rows = (await pool.query('SELECT who FROM t ORDER BY id')).rows.map((r) => r.who);
    expect(rows).toContain('good');
    expect(rows).toContain('bystander');
    expect(rows.filter((w) => w.startsWith('bad'))).toHaveLength(0);
  });

  test('plain pool queries queue behind an open transaction instead of joining it', async () => {
    const order = [];
    const client = await pool.connect();
    await client.query('BEGIN');
    await client.query('INSERT INTO t (who) VALUES ($1)', ['tx']);

    const bystander = pool
      .query('INSERT INTO t (who) VALUES (?)', ['queued'])
      .then(() => order.push('bystander-ran'));

    // Give the bystander a chance to (incorrectly) run inside the transaction.
    await new Promise((resolve) => setTimeout(resolve, 20));
    order.push('rollback');
    await client.query('ROLLBACK');
    client.release();
    await bystander;

    expect(order).toEqual(['rollback', 'bystander-ran']);
    const rows = (await pool.query('SELECT who FROM t')).rows.map((r) => r.who);
    expect(rows).toEqual(['queued']); // tx row rolled back, bystander survived
  });

  test('double release is harmless and the pool stays usable', async () => {
    const client = await pool.connect();
    client.release();
    client.release();
    const result = await pool.query('SELECT 1 AS one');
    expect(result.rows[0].one).toBe(1);
  });
});

describe('AuthRepository against the SQLite schema', () => {
  let pool;
  let repo;

  beforeEach(async () => {
    pool = createPool();
    repo = new AuthRepository({ db: pool, dialect: sqliteDialect });
    await insertUser(pool, { username: 'normal', allowedApps: ['Portal', 'mbkauthe'] });
  });

  afterEach(async () => {
    await pool.end();
  });

  test('schema seeds the support SuperAdmin user', async () => {
    const row = (await pool.query({
      text: 'SELECT "UserName", "Role", "Active", "PasswordEnc" FROM "Users" WHERE "UserName" = $1',
      values: ['support']
    })).rows[0];
    expect(row).toBeDefined();
    expect(row.Role).toBe('SuperAdmin');
    expect(row.Active).toBe(1);
    expect(row.PasswordEnc).toBeTruthy();
  });

  test('getUserWithTwoFA returns the pg-compatible login row shape', async () => {
    const user = await repo.getUserWithTwoFA('normal');
    expect(user.UserName).toBe('normal');
    expect(user.Active).toBeTruthy();
    expect(Array.isArray(user.AllowedApps)).toBe(true);
    // The login route's app-authorization check must not throw.
    expect(user.AllowedApps.some((app) => app && app.toLowerCase() === 'mbkauthe')).toBe(true);
    expect(user.TwoFAStatus ?? null).toBeNull(); // LEFT JOIN with no TwoFA row
  });

  test('insertAppSession stores a Date expiry and returns a UUID id', async () => {
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
    const inserted = await repo.insertAppSession('normal', expiresAt, JSON.stringify({ ip: '::1' }));
    expect(inserted.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);

    const session = await repo.fetchActiveSession(inserted.id);
    expect(session.UserName).toBe('normal');
    expect(session.expires_at).toBeInstanceOf(Date);
    expect(session.expires_at > new Date()).toBe(true);
  });

  test('cleanupAndCountUserSessions deletes expired rows and counts the rest', async () => {
    await repo.insertAppSession('normal', new Date(Date.now() - 5000), null); // expired
    await repo.insertAppSession('normal', new Date(Date.now() + 3600000), null); // live
    await repo.insertAppSession('normal', null, null); // no expiry -> kept

    const count = await repo.cleanupAndCountUserSessions('normal');
    expect(count).toBe(2);
  });

  test('deleteOldestSessionsForUser prunes by created_at with a bound LIMIT', async () => {
    // created_at has second precision; force distinct ordering explicitly.
    for (let i = 0; i < 3; i += 1) {
      const inserted = await repo.insertAppSession('normal', null, null);
      await pool.query({
        text: 'UPDATE "Sessions" SET created_at = $1 WHERE id = $2',
        values: [new Date(Date.UTC(2030, 0, 1, 0, 0, i)), inserted.id]
      });
    }
    const deleted = await repo.deleteOldestSessionsForUser('normal', 2);
    expect(deleted).toBe(2);
    expect(await repo.countActiveSessionsForUser('normal')).toBe(1);
  });

  test('deleteSessionsByIds expands ANY($1) into an IN list', async () => {
    const a = await repo.insertAppSession('normal', null, null);
    const b = await repo.insertAppSession('normal', null, null);
    const deleted = await repo.deleteSessionsByIds([a.id, b.id]);
    expect(deleted).toBe(2);
  });

  test('getSessionValidity falls back to the session-store expire via CASE subquery', async () => {
    const inserted = await repo.insertAppSession('normal', null, null);
    await pool.query(
      'INSERT INTO "session" (sid, sess, expire) VALUES (?, ?, ?)',
      ['store-sid', '{}', '2030-06-01 12:00:00']
    );
    const row = await repo.getSessionValidity(inserted.id, 'store-sid');
    expect(row.expires_at).toBeNull();
    expect(row.connect_expire).toBeInstanceOf(Date);
    expect(row.connect_expire.toISOString()).toBe('2030-06-01T12:00:00.000Z');
  });

  test('updateLastLoginReturnProfile updates and returns profile columns', async () => {
    const profile = await repo.updateLastLoginReturnProfile('normal');
    expect(profile).toHaveProperty('FullName');
    expect(profile).toHaveProperty('Image');

    const row = (await pool.query('SELECT last_login FROM "Users" WHERE "UserName" = ?', ['normal'])).rows[0];
    expect(row.last_login).toBeInstanceOf(Date);
  });

  test('touchTrustedDevice (sqlite branch) touches and joins user data in two steps', async () => {
    await repo.insertTrustedDevice({
      username: 'normal',
      deviceTokenHash: 'device-hash',
      deviceName: 'laptop',
      userAgent: 'jest',
      ipAddress: '::1',
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
    });

    const row = await repo.touchTrustedDevice('device-hash', 'normal');
    expect(row.UserName).toBe('normal');
    expect(row.ExpiresAt).toBeInstanceOf(Date);
    expect(row.Active).toBeTruthy();
    expect(Array.isArray(row.AllowedApps)).toBe(true);
  });

  test('touchTrustedDevice returns null for expired or unknown devices', async () => {
    await repo.insertTrustedDevice({
      username: 'normal',
      deviceTokenHash: 'stale-hash',
      deviceName: null,
      userAgent: null,
      ipAddress: null,
      expiresAt: new Date(Date.now() - 1000)
    });
    expect(await repo.touchTrustedDevice('stale-hash', 'normal')).toBeNull();
    expect(await repo.touchTrustedDevice('missing-hash', 'normal')).toBeNull();
  });

  test('getApiTokenByHash returns parsed Permissions and user apps', async () => {
    await pool.query({
      text: 'INSERT INTO "ApiTokens" ("UserName", "Name", "TokenHash", "Prefix", "Permissions") VALUES ($1, $2, $3, $4, $5)',
      values: ['normal', 'ci-token', 'token-hash', 'mbk_', JSON.stringify({ scope: 'write', allowedApps: ['mbkauthe'] })]
    });
    const row = await repo.getApiTokenByHash('token-hash');
    expect(row.Permissions).toEqual({ scope: 'write', allowedApps: ['mbkauthe'] });
    expect(Array.isArray(row.user_allowed_apps)).toBe(true);
    expect(row.Active).toBeTruthy();
  });

  test('updateApiTokenLastUsed (sqlite branch) throttles by interval', async () => {
    await pool.query({
      text: 'INSERT INTO "ApiTokens" ("UserName", "Name", "TokenHash", "Prefix") VALUES ($1, $2, $3, $4)',
      values: ['normal', 'ci-token', 'token-hash', 'mbk_']
    });
    const { id } = (await pool.query('SELECT id FROM "ApiTokens" WHERE "TokenHash" = ?', ['token-hash'])).rows[0];

    const first = await repo.updateApiTokenLastUsed(id);
    expect(first.rowCount).toBe(1); // LastUsed was NULL
    const second = await repo.updateApiTokenLastUsed(id);
    expect(second.rowCount).toBe(0); // just touched -> inside 15-minute window
  });

  test('withTransaction commits work and rolls back failures atomically', async () => {
    await repo.withTransaction(async (txRepo) => {
      await txRepo.advisoryTransactionLock('sessions:normal'); // no-op on sqlite
      await txRepo.insertAppSession('normal', null, null);
    });
    expect(await repo.countActiveSessionsForUser('normal')).toBe(1);

    await expect(
      repo.withTransaction(async (txRepo) => {
        await txRepo.insertAppSession('normal', null, null);
        throw new Error('boom');
      })
    ).rejects.toThrow('boom');
    expect(await repo.countActiveSessionsForUser('normal')).toBe(1);
  });
});

describe('SqliteSessionStore', () => {
  let pool;
  let store;

  const storeGet = (sid) => new Promise((resolve, reject) => {
    store.get(sid, (err, sess) => (err ? reject(err) : resolve(sess)));
  });
  const storeSet = (sid, sess) => new Promise((resolve, reject) => {
    store.set(sid, sess, (err) => (err ? reject(err) : resolve()));
  });
  const storeDestroy = (sid) => new Promise((resolve, reject) => {
    store.destroy(sid, (err) => (err ? reject(err) : resolve()));
  });
  const storeTouch = (sid, sess) => new Promise((resolve, reject) => {
    store.touch(sid, sess, (err) => (err ? reject(err) : resolve()));
  });
  const storeLength = () => new Promise((resolve, reject) => {
    store.length((err, n) => (err ? reject(err) : resolve(n)));
  });
  const storeAll = () => new Promise((resolve, reject) => {
    store.all((err, sessions) => (err ? reject(err) : resolve(sessions)));
  });
  const storeClear = () => new Promise((resolve, reject) => {
    store.clear((err) => (err ? reject(err) : resolve()));
  });

  const sessionData = (maxAgeMs) => ({
    cookie: { maxAge: maxAgeMs },
    user: { UserName: 'normal', role: 'NormalUser' }
  });

  beforeEach(async () => {
    pool = createPool();
    store = new SqliteSessionStore({ db: pool, tableName: 'session', createTableIfMissing: true });
    await insertUser(pool, { username: 'normal' });
  });

  afterEach(async () => {
    await pool.end();
  });

  test('set then get round-trips session JSON', async () => {
    await storeSet('sid-1', sessionData(60000));
    const sess = await storeGet('sid-1');
    expect(sess.user.UserName).toBe('normal');
    expect(sess.cookie.maxAge).toBe(60000);
  });

  test('set upserts on conflict and records the username column', async () => {
    await storeSet('sid-1', sessionData(60000));
    await storeSet('sid-1', { ...sessionData(60000), user: { UserName: 'normal', role: 'SuperAdmin' } });

    const sess = await storeGet('sid-1');
    expect(sess.user.role).toBe('SuperAdmin');
    expect(await storeLength()).toBe(1);

    const row = (await pool.query('SELECT username FROM "session" WHERE sid = ?', ['sid-1'])).rows[0];
    expect(row.username).toBe('normal');
  });

  test('get returns undefined for a missing sid', async () => {
    expect(await storeGet('nope')).toBeUndefined();
  });

  test('get treats an expired session as missing and deletes the row', async () => {
    await storeSet('sid-exp', sessionData(-1000)); // negative maxAge -> already expired
    expect(await storeGet('sid-exp')).toBeUndefined();
    expect(await storeLength()).toBe(0);
  });

  test('destroy removes the session row', async () => {
    await storeSet('sid-1', sessionData(60000));
    await storeDestroy('sid-1');
    expect(await storeGet('sid-1')).toBeUndefined();
  });

  test('touch extends the expiry', async () => {
    await storeSet('sid-1', sessionData(60000));
    const before = (await pool.query('SELECT expire FROM "session" WHERE sid = ?', ['sid-1'])).rows[0].expire;

    await storeTouch('sid-1', sessionData(60 * 60 * 1000));
    const after = (await pool.query('SELECT expire FROM "session" WHERE sid = ?', ['sid-1'])).rows[0].expire;
    expect(after > before).toBe(true); // CURRENT_TIMESTAMP text sorts chronologically
  });

  test('touch is a no-op when disableTouch is set (production config)', async () => {
    const quietStore = new SqliteSessionStore({ db: pool, tableName: 'session', disableTouch: true });
    await storeSet('sid-1', sessionData(60000));
    const before = (await pool.query('SELECT expire FROM "session" WHERE sid = ?', ['sid-1'])).rows[0].expire;

    await new Promise((resolve, reject) => {
      quietStore.touch('sid-1', sessionData(60 * 60 * 1000), (err) => (err ? reject(err) : resolve()));
    });
    const after = (await pool.query('SELECT expire FROM "session" WHERE sid = ?', ['sid-1'])).rows[0].expire;
    expect(after).toBe(before);
  });

  test('all and clear cover the remaining store surface', async () => {
    await storeSet('sid-1', sessionData(60000));
    await storeSet('sid-2', sessionData(60000));

    const sessions = await storeAll();
    expect(sessions.map((s) => s.sid).sort()).toEqual(['sid-1', 'sid-2']);

    await storeClear();
    expect(await storeLength()).toBe(0);
  });

  test('login regenerate sequence: destroy old sid then set new sid', async () => {
    // Mirrors express-session's Store.regenerate() during completeLoginProcess.
    await storeSet('old-sid', sessionData(60000));
    await storeDestroy('old-sid');
    await storeSet('new-sid', sessionData(60000));

    expect(await storeGet('old-sid')).toBeUndefined();
    const sess = await storeGet('new-sid');
    expect(sess.user.UserName).toBe('normal');
  });
});
