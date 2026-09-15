import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { IDatabaseAdapter, QueryOptions, QueryResult } from "./IDatabaseAdapter.js";
import { Mutex, SqliteClient } from "./SqliteMutex.js";
import { translatePgToSqlite } from "../schema/ddlTranslate.js";
import { sqliteDialect } from "../dialects/SqliteDialect.js";
import { IDialect } from "../dialects/IDialect.js";

function normalizeQueryArgs(queryOrText: string | QueryOptions, maybeValues?: any[]): { text: string; values: any[]; name?: string } {
  if (typeof queryOrText === "string") {
    return { text: queryOrText, values: maybeValues || [], name: undefined };
  }
  if (queryOrText && typeof queryOrText === "object") {
    return {
      text: queryOrText.text ?? "",
      values: queryOrText.values ?? (maybeValues || []),
      name: queryOrText.name,
    };
  }
  return { text: String(queryOrText ?? ""), values: maybeValues || [], name: undefined };
}

function coerceBindValue(value: any): any {
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

function createRowNormalizer(options: { jsonColumns: Set<string>; booleanColumns: Set<string>; timestampColumns: Set<string> }) {
  const { jsonColumns, booleanColumns, timestampColumns } = options;
  return function normalizeRow<T = any>(row: any): T {
    if (!row || typeof row !== "object") return row;
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
    return row as T;
  };
}

function runQuery(db: any, rawText: string, rawValues: any[], normalizeRow: (row: any) => any): QueryResult {
  const trimmed = String(rawText || "").trim();
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

export interface SqliteAdapterOptions {
  jsonColumns?: string[];
  booleanColumns?: string[];
  timestampColumns?: string[];
  filePath?: string;
}

export class SqliteAdapter implements IDatabaseAdapter {
  public name = "sqlite";
  public dialect: IDialect = sqliteDialect;
  public db: any;
  public filePath: string | null = null;
  private _mutex: Mutex = new Mutex();
  private _normalizeRow: (row: any) => any;

  constructor(filePathOrDb: string | any, options: SqliteAdapterOptions = {}) {
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

    this._normalizeRow = createRowNormalizer({
      jsonColumns: new Set([...DEFAULT_JSON_COLUMNS, ...(options.jsonColumns || [])]),
      booleanColumns: new Set(options.booleanColumns || []),
      timestampColumns: new Set([...DEFAULT_TIMESTAMP_COLUMNS, ...(options.timestampColumns || [])]),
    });
  }

  async query<T = any>(queryOrText: string | QueryOptions, maybeValues?: any[]): Promise<QueryResult<T>> {
    const { text, values } = normalizeQueryArgs(queryOrText, maybeValues);
    const release = await this._mutex.acquire();
    try {
      return runQuery(this.db, text, values, this._normalizeRow) as QueryResult<T>;
    } finally {
      release();
    }
  }

  async connect(): Promise<SqliteClient> {
    const release = await this._mutex.acquire();
    const queryFn = async (db: any, queryOrText: any, maybeValues?: any[]) => {
      const { text, values } = normalizeQueryArgs(queryOrText, maybeValues);
      return runQuery(db, text, values, this._normalizeRow);
    };
    return new SqliteClient(this.db, release, queryFn);
  }

  exec(sql: string): void {
    if (this.db && typeof this.db.exec === "function") {
      this.db.exec(sql);
    }
  }

  execScript(sql: string): void {
    this.exec(sql);
  }

  pragma(sql: string): any {
    if (this.db && typeof this.db.pragma === "function") {
      return this.db.pragma(sql);
    }
    return undefined;
  }

  close(): void {
    if (this.db && typeof this.db.close === "function") {
      try {
        this.db.close();
      } catch {}
    }
  }

  async end(): Promise<void> {
    this.close();
  }
}

export class SqlitePool extends SqliteAdapter {}

export { Mutex, SqliteClient };
export default SqliteAdapter;
