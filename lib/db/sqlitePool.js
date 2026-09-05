import Database from "better-sqlite3";
import { translatePgToSqlite } from "./sqlSqliteTranslate.js";

class Mutex {
  constructor() {
    this._tail = Promise.resolve();
  }

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

function coerceBindValue(value) {
  if (value === undefined) return null;
  if (typeof value === "boolean") return value ? 1 : 0;
  if (value instanceof Date) return value.toISOString().slice(0, 19).replace("T", " ");
  if (typeof value === "object" && value !== null && !Buffer.isBuffer(value)) return JSON.stringify(value);
  return value;
}

const JSON_COLUMNS = new Set([
  "allowed_apps", "user_allowed_apps", "permissions", "positions", "social_accounts", "meta"
]);

const TIMESTAMP_COLUMNS = new Set([
  "expires_at", "created_at", "updated_at", "last_login", "last_activity",
  "connect_expire", "last_used", "approved_at", "reset_token_expires", "last_reset_attempt"
]);

const SQLITE_TIMESTAMP_RE = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)(Z)?$/;

function normalizeRow(row) {
  for (const [key, value] of Object.entries(row)) {
    if (typeof value !== "string") continue;
    if (JSON_COLUMNS.has(key)) {
      try { row[key] = JSON.parse(value); } catch {}
    } else if (TIMESTAMP_COLUMNS.has(key)) {
      const m = SQLITE_TIMESTAMP_RE.exec(value);
      if (m) row[key] = new Date(`${m[1]}T${m[2]}Z`);
    }
  }
  return row;
}

function runQuery(db, rawText, rawValues) {
  const trimmed = rawText.trim();
  const upper = trimmed.toUpperCase();

  if (["BEGIN", "COMMIT", "ROLLBACK"].includes(upper)) {
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

  execScript(sql) {
    this.db.exec(sql);
  }

  async end() {
    this.db.close();
  }
}
