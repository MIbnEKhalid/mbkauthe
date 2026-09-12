import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { Mutex, SqliteClient } from "./sqliteMutex.js";
import { translatePgToSqlite } from "./sqlSqliteTranslate.js";
import { sqliteDialect } from "./dialects/sqlite.js";

function normalizeQueryArgs(queryOrText, maybeValues) {
  if (typeof queryOrText === "string") return { text: queryOrText, values: maybeValues || [], name: undefined };
  return { text: queryOrText?.text ?? "", values: queryOrText?.values ?? (maybeValues || []), name: queryOrText?.name };
}

function coerceBindValue(value) {
  if (value === undefined) return null;
  if (typeof value === "boolean") return value ? 1 : 0;
  if (value instanceof Date) return value.toISOString().slice(0, 19).replace("T", " ");
  if (typeof value === "object" && value !== null && !Buffer.isBuffer(value)) return JSON.stringify(value);
  return value;
}

const DEFAULT_JSON_COLUMNS = [
  "allowed_apps", "user_allowed_apps", "permissions", "positions",
  "social_accounts", "meta", "conversation_history", "allowed_record_types", "sections", "semester"
];

const DEFAULT_TIMESTAMP_COLUMNS = [
  "expires_at", "created_at", "updated_at", "last_login", "last_activity",
  "connect_expire", "last_used", "approved_at", "reset_token_expires",
  "resetTokenExpires", "lastResetAttempt", "last_reset_attempt", "deadline", "completed_at", "start_date"
];

const SQLITE_TIMESTAMP_RE = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)(Z)?$/;

function createRowNormalizer({ jsonColumns, booleanColumns, timestampColumns }) {
  return function normalizeRow(row) {
    if (!row) return row;
    for (const [key, value] of Object.entries(row)) {
      if (typeof value === "string") {
        if (jsonColumns.has(key)) {
          try { row[key] = JSON.parse(value); } catch {}
        } else if (timestampColumns.has(key)) {
          const m = SQLITE_TIMESTAMP_RE.exec(value);
          if (m) row[key] = new Date(`${m[1]}T${m[2]}Z`);
        }
      }
      if (booleanColumns.has(key) && value !== null && value !== undefined) {
        row[key] = Boolean(value);
      }
    }
    return row;
  };
}

function runQuery(db, rawText, rawValues, normalizeRow) {
  const trimmed = rawText.trim();
  const upper = trimmed.toUpperCase();

  if (["BEGIN", "COMMIT", "ROLLBACK"].includes(upper)) {
    db.exec(upper);
    return { rows: [], rowCount: 0, command: upper };
  }

  if (/^\s*(CREATE|DROP|ALTER|ANALYZE|ATTACH|DETACH|REINDEX|RELEASE|SAVEPOINT|VACUUM)\b/i.test(trimmed)) {
    db.exec(trimmed);
    return { rows: [], rowCount: 0, command: "DDL" };
  }

  const { text, values } = translatePgToSqlite(trimmed, rawValues);
  const stmt = db.prepare(text);
  const bindValues = values.map(coerceBindValue);

  if (stmt.reader || /\bRETURNING\b/i.test(text)) {
    const rows = stmt.all(...bindValues).map(normalizeRow);
    return { rows, rowCount: rows.length, command: stmt.reader ? "SELECT" : "EXECUTE" };
  }

  const info = stmt.run(...bindValues);
  return { rows: [], rowCount: info.changes, command: "EXECUTE", lastInsertRowid: info.lastInsertRowid };
}

/**
 * Universal SQLite database adapter and pool wrapper.
 */
export class SqliteAdapter {
  constructor(filePathOrDb, options = {}) {
    if (typeof filePathOrDb === "string") {
      this.filePath = filePathOrDb;
      if (filePathOrDb !== ":memory:") {
        const dir = path.dirname(path.resolve(filePathOrDb));
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      }
      this.db = new Database(filePathOrDb);
      try {
        this.db.pragma("journal_mode = WAL");
        this.db.pragma("foreign_keys = ON");
      } catch {}
    } else {
      this.db = filePathOrDb;
      this.filePath = options.filePath || null;
    }

    this.dialect = options.dialect || sqliteDialect;
    this.mutex = new Mutex();
    this._normalizeRow = createRowNormalizer({
      jsonColumns: new Set([...DEFAULT_JSON_COLUMNS, ...(options.jsonColumns || [])]),
      booleanColumns: new Set(options.booleanColumns || []),
      timestampColumns: new Set([...DEFAULT_TIMESTAMP_COLUMNS, ...(options.timestampColumns || [])])
    });
  }

  async query(queryOrText, maybeValues) {
    const { text, values } = normalizeQueryArgs(queryOrText, maybeValues);
    const release = await this.mutex.acquire();
    try {
      return runQuery(this.db, text, values, this._normalizeRow);
    } finally {
      release();
    }
  }

  async connect() {
    const release = await this.mutex.acquire();
    return new SqliteClient(this.db, release, (db, queryOrText, maybeValues) => {
      const { text, values } = normalizeQueryArgs(queryOrText, maybeValues);
      return runQuery(db, text, values, this._normalizeRow);
    });
  }

  exec(sql) { this.db.exec(sql); }
  execScript(sql) { this.db.exec(sql); }
  close() { try { this.db.close(); } catch {} }
  async end() { this.close(); }
}

export const SqlitePool = SqliteAdapter;
export { Mutex, SqliteClient };
export default SqliteAdapter;
