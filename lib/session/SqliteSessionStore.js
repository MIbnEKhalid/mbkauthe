import session from "express-session";

const Store = session.Store;

// SQLite's CURRENT_TIMESTAMP format ('YYYY-MM-DD HH:MM:SS', UTC) — used so
// this store's `expire` column sorts/compares correctly against any other
// CURRENT_TIMESTAMP-derived timestamp text elsewhere in the SQLite schema.
function toSqliteTimestamp(date) {
  return date.toISOString().slice(0, 19).replace("T", " ");
}

/**
 * express-session store for the SQLite backend. Mirrors the table shape and
 * public behavior of connect-pg-simple (same "session" table: sid, sess,
 * expire, username, last_activity) so admin/cleanup queries elsewhere in
 * mbkauthe that read the "session" table work unchanged across both
 * database backends.
 */
export class SqliteSessionStore extends Store {
  constructor({ db, tableName = "session", createTableIfMissing = false, disableTouch = false } = {}) {
    super();
    if (!db) throw new Error("[mbkauthe] SqliteSessionStore requires a `db` (SqlitePool) instance");
    this.db = db;
    this.tableName = tableName;
    this.disableTouch = disableTouch;

    if (createTableIfMissing) {
      this.db.execScript(`
        CREATE TABLE IF NOT EXISTS "${this.tableName}" (
          sid TEXT PRIMARY KEY,
          sess TEXT NOT NULL,
          expire TEXT NOT NULL,
          username TEXT,
          last_activity TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_${this.tableName}_expire ON "${this.tableName}" (expire);
      `);
    }
  }

  get(sid, callback) {
    this.db.query(`SELECT sess, expire FROM "${this.tableName}" WHERE sid = ?`, [sid])
      .then((result) => {
        const row = result.rows?.[0];
        if (!row) return callback(null, undefined);

        if (row.expire && new Date(row.expire.replace(" ", "T") + "Z").getTime() <= Date.now()) {
          return this.destroy(sid, (err) => callback(err, undefined));
        }

        try {
          callback(null, JSON.parse(row.sess));
        } catch (err) {
          callback(err);
        }
      })
      .catch(callback);
  }

  set(sid, sessionData, callback) {
    const maxAge = sessionData.cookie?.maxAge;
    const expireDate = typeof maxAge === "number"
      ? new Date(Date.now() + maxAge)
      : new Date(Date.now() + 24 * 60 * 60 * 1000);

    const sess = JSON.stringify(sessionData);
    const expire = toSqliteTimestamp(expireDate);
    const username = sessionData.user?.UserName ?? sessionData.UserName ?? null;

    this.db.query(
      `INSERT INTO "${this.tableName}" (sid, sess, expire, username, last_activity)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expire = excluded.expire,
         username = excluded.username, last_activity = excluded.last_activity`,
      [sid, sess, expire, username, toSqliteTimestamp(new Date())]
    )
      .then(() => callback?.(null))
      .catch((err) => callback?.(err));
  }

  destroy(sid, callback) {
    this.db.query(`DELETE FROM "${this.tableName}" WHERE sid = ?`, [sid])
      .then(() => callback?.(null))
      .catch((err) => callback?.(err));
  }

  touch(sid, sessionData, callback) {
    if (this.disableTouch) return callback?.(null);

    const maxAge = sessionData.cookie?.maxAge;
    const expireDate = typeof maxAge === "number"
      ? new Date(Date.now() + maxAge)
      : new Date(Date.now() + 24 * 60 * 60 * 1000);

    this.db.query(
      `UPDATE "${this.tableName}" SET expire = ?, last_activity = ? WHERE sid = ?`,
      [toSqliteTimestamp(expireDate), toSqliteTimestamp(new Date()), sid]
    )
      .then(() => callback?.(null))
      .catch((err) => callback?.(err));
  }

  all(callback) {
    this.db.query(`SELECT sid, sess FROM "${this.tableName}"`, [])
      .then((result) => {
        try {
          const sessions = (result.rows || []).map((row) => ({ sid: row.sid, ...JSON.parse(row.sess) }));
          callback(null, sessions);
        } catch (err) {
          callback(err);
        }
      })
      .catch(callback);
  }

  length(callback) {
    this.db.query(`SELECT COUNT(*) AS count FROM "${this.tableName}"`, [])
      .then((result) => callback(null, Number(result.rows?.[0]?.count ?? 0)))
      .catch(callback);
  }

  clear(callback) {
    this.db.query(`DELETE FROM "${this.tableName}"`, [])
      .then(() => callback?.(null))
      .catch((err) => callback?.(err));
  }
}
