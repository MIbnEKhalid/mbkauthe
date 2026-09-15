import session from "express-session";

const toSqliteTimestamp = (date: Date): string => date.toISOString().slice(0, 19).replace("T", " ");

export interface SqliteSessionStoreOptions {
  db: any;
  tableName?: string;
  createTableIfMissing?: boolean;
  disableTouch?: boolean;
}

export class SqliteSessionStore extends session.Store {
  private db: any;
  private tableName: string;
  private disableTouch: boolean;

  constructor({ db, tableName = "mbkcore_session", createTableIfMissing = false, disableTouch = false }: SqliteSessionStoreOptions = { db: null }) {
    super();
    if (!db) throw new Error("[mbkauthe] SqliteSessionStore requires a `db` instance");
    this.db = db;
    this.tableName = tableName;
    this.disableTouch = disableTouch;

    if (createTableIfMissing) {
      const sql = `
        CREATE TABLE IF NOT EXISTS "${this.tableName}" (
          sid TEXT PRIMARY KEY,
          sess TEXT NOT NULL,
          expire TEXT NOT NULL,
          username VARCHAR(50),
          last_activity TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_${this.tableName}_expire ON "${this.tableName}" (expire);
      `;
      try {
        if (typeof this.db.execScript === "function") {
          this.db.execScript(sql);
        } else if (typeof this.db.exec === "function") {
          this.db.exec(sql);
        } else if (this.db.db && typeof this.db.db.exec === "function") {
          this.db.db.exec(sql);
        } else if (typeof this.db.query === "function") {
          this.db.query(sql).catch(() => {});
        }
      } catch {}
    }
  }

  get(sid: string, callback: (err?: any, session?: session.SessionData | null) => void): void {
    this.db.query(`SELECT sess, expire FROM "${this.tableName}" WHERE sid = ?`, [sid])
      .then((result: any) => {
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

  set(sid: string, session_data: session.SessionData, callback?: (err?: any) => void): void {
    const max_age = session_data.cookie?.maxAge;
    const expire_date = typeof max_age === "number" ? new Date(Date.now() + max_age) : new Date(Date.now() + 86400000);
    const sess = JSON.stringify(session_data);
    const expire = toSqliteTimestamp(expire_date);
    const username = (session_data as any).user?.username ?? null;

    this.db.query(
      `INSERT INTO "${this.tableName}" (sid, sess, expire, username, last_activity)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expire = excluded.expire,
         username = excluded.username, last_activity = excluded.last_activity`,
      [sid, sess, expire, username, toSqliteTimestamp(new Date())]
    )
      .then(() => callback?.(null))
      .catch((err: any) => callback?.(err));
  }

  destroy(sid: string, callback?: (err?: any) => void): void {
    this.db.query(`DELETE FROM "${this.tableName}" WHERE sid = ?`, [sid])
      .then(() => callback?.(null))
      .catch((err: any) => callback?.(err));
  }

  touch(sid: string, session_data: session.SessionData, callback?: (err?: any) => void): void {
    if (this.disableTouch) return callback?.(null);
    const max_age = session_data.cookie?.maxAge;
    const expire_date = typeof max_age === "number" ? new Date(Date.now() + max_age) : new Date(Date.now() + 86400000);

    this.db.query(
      `UPDATE "${this.tableName}" SET expire = ?, last_activity = ? WHERE sid = ?`,
      [toSqliteTimestamp(expire_date), toSqliteTimestamp(new Date()), sid]
    )
      .then(() => callback?.(null))
      .catch((err: any) => callback?.(err));
  }

  all(callback: (err?: any, obj?: session.SessionData[] | { [sid: string]: session.SessionData } | null) => void): void {
    this.db.query(`SELECT sid, sess FROM "${this.tableName}"`, [])
      .then((result: any) => {
        try {
          callback(null, (result.rows || []).map((row: any) => ({ sid: row.sid, ...JSON.parse(row.sess) })));
        } catch (err) {
          callback(err);
        }
      })
      .catch(callback);
  }

  length(callback: (err?: any, length?: number) => void): void {
    this.db.query(`SELECT COUNT(*) AS count FROM "${this.tableName}"`, [])
      .then((result: any) => callback(null, Number(result.rows?.[0]?.count ?? 0)))
      .catch(callback);
  }

  clear(callback?: (err?: any) => void): void {
    this.db.query(`DELETE FROM "${this.tableName}"`, [])
      .then(() => callback?.(null))
      .catch((err: any) => callback?.(err));
  }
}

export default SqliteSessionStore;
