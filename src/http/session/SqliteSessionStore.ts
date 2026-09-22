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
          sid TEXT PRIMARY KEY DEFAULT (
            lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' ||
            substr(lower(hex(randomblob(2))), 2) || '-' ||
            substr('89ab', (abs(random()) % 4) + 1, 1) || substr(lower(hex(randomblob(2))), 2) || '-' ||
            lower(hex(randomblob(6)))
          ),
          id TEXT GENERATED ALWAYS AS (sid) VIRTUAL,
          sess TEXT DEFAULT '{}' NOT NULL,
          expire TEXT,
          username VARCHAR(50),
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          last_activity TEXT DEFAULT CURRENT_TIMESTAMP,
          meta TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_${this.tableName}_expire ON "${this.tableName}" (expire);
        CREATE INDEX IF NOT EXISTS idx_${this.tableName}_username ON "${this.tableName}" (username);
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
    const query = `
      SELECT s.sess, s.expire, s.sid AS session_id,
             u.username, u.user_id, u.is_active, u.is_local_only, u.role, u.allowed_apps, u.full_name, u.image
      FROM "${this.tableName}" s
      LEFT JOIN mbkcore_users u ON u.username = s.username
      WHERE s.sid = ?
      LIMIT 1
    `;
    this.db.query(query, [sid])
      .then((result: any) => {
        const row = result.rows?.[0];
        if (!row) return callback(null, undefined);
        const isExpired = row.expire && new Date(row.expire.replace(" ", "T") + "Z").getTime() <= Date.now();
        if (isExpired) {
          try {
            const parsed = typeof row.sess === "string" ? JSON.parse(row.sess) : row.sess;
            if (!parsed?.user?.session_id) {
              return this.destroy(sid, (err) => callback(err, undefined));
            }
          } catch {
            return this.destroy(sid, (err) => callback(err, undefined));
          }
        }
        try {
          const sessObj = typeof row.sess === "string" ? JSON.parse(row.sess) : row.sess;
          if (row.username && row.session_id) {
            let allowed = row.allowed_apps;
            if (typeof allowed === "string") {
              try { allowed = JSON.parse(allowed); } catch {}
            }
            sessObj._liveAuth = {
              session_id: row.session_id,
              user_id: row.user_id,
              username: row.username,
              is_active: Boolean(row.is_active),
              is_local_only: Boolean(row.is_local_only && row.is_local_only !== "0" && row.is_local_only !== "false"),
              role: row.role,
              allowed_apps: allowed,
              full_name: row.full_name,
              image: row.image,
              expires_at: row.expire,
            };
          } else {
            sessObj._liveAuth = null;
          }
          callback(null, sessObj);
        } catch (err) {
          callback(err);
        }
      })
      .catch((err: any) => {
        // Fallback to basic query if joined query encounters schema issues
        this.db.query(`SELECT sess, expire FROM "${this.tableName}" WHERE sid = ? LIMIT 1`, [sid])
          .then((fallbackResult: any) => {
            const fallbackRow = fallbackResult.rows?.[0];
            if (!fallbackRow) return callback(null, undefined);
            try {
              const sessObj = typeof fallbackRow.sess === "string" ? JSON.parse(fallbackRow.sess) : fallbackRow.sess;
              callback(null, sessObj);
            } catch (jsonErr) {
              callback(jsonErr);
            }
          })
          .catch(() => callback(err));
      });
  }

  set(sid: string, session_data: session.SessionData, callback?: (err?: any) => void): void {
    const max_age = session_data.cookie?.maxAge;
    const expire_date = typeof max_age === "number" ? new Date(Date.now() + max_age) : new Date(Date.now() + 86400000);
    const sess = JSON.stringify(session_data);
    const expire = toSqliteTimestamp(expire_date);
    const username = (session_data as any).user?.username ?? null;
    const now = toSqliteTimestamp(new Date());

    this.db.query(
      `INSERT INTO "${this.tableName}" (sid, sess, expire, username, last_activity)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expire = excluded.expire,
         username = COALESCE(excluded.username, "${this.tableName}".username),
         last_activity = excluded.last_activity`,
      [sid, sess, expire, username, now]
    )
      .then(() => callback?.(null))
      .catch((err: any) => callback?.(err));
  }

  destroy(sid: string, callback?: (err?: any) => void): void {
    this.db.query(`DELETE FROM "${this.tableName}" WHERE sid = ?`, [sid])
      .then(() => callback?.(null))
      .catch((err: any) => callback?.(err));
  }

  regenerate(req: any, fn: (err?: any) => void): void {
    if (req?.session?.user) {
      (this as any).generate(req);
      fn?.();
    } else {
      this.destroy(req.sessionID, (err: any) => {
        (this as any).generate(req);
        fn?.(err);
      });
    }
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
