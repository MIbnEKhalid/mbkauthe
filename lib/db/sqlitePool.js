import Database from "better-sqlite3";
import { translatePgToSqlite } from "./sqlSqliteTranslate.js";

/**
 * FIFO promise mutex. All statements run on ONE shared better-sqlite3
 * handle, and BEGIN/COMMIT are connection state — so a transaction must
 * hold exclusive access for its whole (async) lifetime, or queries from
 * other requests interleave between its awaits and silently join it
 * (or a second BEGIN throws "cannot start a transaction within a
 * transaction"). Individual statements are synchronous, so waiters queue
 * for microseconds, not I/O time.
 */
class Mutex {
  constructor() {
    this._tail = Promise.resolve();
  }

  /** Resolves to a release function once the lock is held. */
  acquire() {
    const prev = this._tail;
    let release;
    this._tail = new Promise((resolve) => {
      let released = false;
      release = () => {
        if (released) return;
        released = true;
        resolve();
      };
    });
    return prev.then(() => release);
  }
}

/**
 * Exclusive handle returned by SqlitePool.connect(). Holds the pool mutex
 * from connect() until release(), so a BEGIN..COMMIT sequence issued on it
 * cannot interleave with queries from other requests. release() is
 * idempotent. Queries on the client itself do NOT re-acquire the mutex —
 * the client is the holder. Do not call pool.query() from code running
 * inside a transaction (use the client / txRepo): it would wait for the
 * lock the transaction is holding and deadlock.
 */
class SqliteClient {
  constructor(db, releaseLock) {
    this.db = db;
    this._releaseLock = releaseLock;
  }

  async query(queryOrText, maybeValues) {
    const { text, values, name } = normalizeQueryArgs(queryOrText, maybeValues);
    return runQuery(this.db, text, values, name);
  }

  release() {
    this._releaseLock();
  }
}

function normalizeQueryArgs(queryOrText, maybeValues) {
  if (typeof queryOrText === "string") {
    return { text: queryOrText, values: maybeValues || [], name: undefined };
  }
  return {
    text: queryOrText?.text ?? "",
    values: queryOrText?.values ?? [],
    name: queryOrText?.name
  };
}

/**
 * better-sqlite3 only binds numbers, strings, bigints, buffers, and null.
 * Coerce the extra types the pg driver would serialize for us: Date ->
 * SQLite's CURRENT_TIMESTAMP text format ('YYYY-MM-DD HH:MM:SS', UTC) so
 * comparisons against CURRENT_TIMESTAMP stay correct, boolean -> 1/0,
 * undefined -> null.
 */
function coerceBindValue(value) {
  if (value === undefined) return null;
  if (typeof value === "boolean") return value ? 1 : 0;
  if (value instanceof Date) {
    return value.toISOString().slice(0, 19).replace("T", " ");
  }
  // pg serializes objects/arrays bound to json/jsonb params; mirror that.
  if (typeof value === "object" && value !== null && !Buffer.isBuffer(value)) {
    return JSON.stringify(value);
  }
  return value;
}

/**
 * Read-side row normalization so results match what the pg driver returns.
 *
 * Postgres jsonb columns arrive as parsed objects/arrays and timestamp
 * columns as Date objects; better-sqlite3 returns raw TEXT for both. All
 * consumers (login app-authorization checks, API-token permissions, expiry
 * comparisons) are written against the pg shapes, so convert by column name
 * — the schema is fixed and known. Timestamp text is UTC (it comes from
 * CURRENT_TIMESTAMP or coerceBindValue), but `new Date('YYYY-MM-DD
 * HH:MM:SS')` would parse it as LOCAL time, skewing every expiry check by
 * the machine's UTC offset — hence the explicit 'Z'.
 *
 * "sess" and "expire" (express-session store) are deliberately NOT listed:
 * SqliteSessionStore owns those columns and does its own JSON/UTC handling.
 */
const JSON_COLUMNS = new Set([
  "AllowedApps",
  "user_allowed_apps", // alias of Users.AllowedApps in getApiTokenByHash
  "Permissions",
  "Positions",
  "SocialAccounts",
  "meta"
]);

const TIMESTAMP_COLUMNS = new Set([
  "expires_at",
  "created_at",
  "updated_at",
  "last_login",
  "last_activity",
  "connect_expire", // alias of session.expire in getSessionValidity
  "CreatedAt",
  "ExpiresAt",
  "LastUsed"
]);

const SQLITE_TIMESTAMP_RE = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)(Z)?$/;

function normalizeRow(row) {
  for (const key of Object.keys(row)) {
    const value = row[key];
    if (typeof value !== "string") continue;

    if (JSON_COLUMNS.has(key)) {
      try {
        row[key] = JSON.parse(value);
      } catch {
        // Not valid JSON — leave the raw string rather than lose data.
      }
    } else if (TIMESTAMP_COLUMNS.has(key)) {
      const m = SQLITE_TIMESTAMP_RE.exec(value);
      if (m) {
        row[key] = new Date(`${m[1]}T${m[2]}Z`);
      }
    }
  }
  return row;
}

function runQuery(db, rawText, rawValues) {
  const trimmed = rawText.trim();
  const upper = trimmed.toUpperCase();

  // Transaction control statements pass straight through.
  if (upper === "BEGIN" || upper === "COMMIT" || upper === "ROLLBACK") {
    db.exec(upper);
    return { rows: [], rowCount: 0, command: upper };
  }

  const { text, values } = translatePgToSqlite(trimmed, rawValues);
  const stmt = db.prepare(text);
  const bindValues = values.map(coerceBindValue);

  if (stmt.reader) {
    const rows = stmt.all(...bindValues).map(normalizeRow);
    return { rows, rowCount: rows.length, command: "SELECT" };
  }

  const info = stmt.run(...bindValues);
  return {
    rows: [],
    rowCount: info.changes,
    command: "EXECUTE",
    lastInsertRowid: info.lastInsertRowid
  };
}

export class SqlitePool {
  constructor(filePath) {
    this.db = new Database(filePath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.mutex = new Mutex();
  }

  async query(queryOrText, maybeValues) {
    const { text, values } = normalizeQueryArgs(queryOrText, maybeValues);
    // Take the mutex per statement so a plain query can never land inside
    // another request's open transaction.
    const release = await this.mutex.acquire();
    try {
      return runQuery(this.db, text, values);
    } finally {
      release();
    }
  }

  async connect() {
    const release = await this.mutex.acquire();
    return new SqliteClient(this.db, release);
  }

  /** Run a raw multi-statement SQL script (schema files, migrations). */
  execScript(sql) {
    this.db.exec(sql);
  }

  async end() {
    this.db.close();
  }
}
