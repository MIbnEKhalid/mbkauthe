import { postgresDialect } from "./dialects/postgres.js";

const isPlainObject = (value) => !!value && typeof value === "object" && !Array.isArray(value);

export class BaseRepository {
  constructor({ db, dialect = postgresDialect } = {}) {
    this.db = db;
    this.dialect = dialect;
  }

  quoteIdentifier(name) {
    if (name === "*") return "*";
    return String(name)
      .split(".")
      .map((part) => (part === "*" ? "*" : this.dialect.quoteIdentifier(part)))
      .join(".");
  }

  ident(name) {
    return { kind: "ident", name };
  }

  value(val) {
    return { kind: "param", value: val };
  }

  raw(text) {
    return { kind: "raw", text: text ?? "" };
  }

  list(values) {
    return { kind: "list", values };
  }

  table(name, alias = null) {
    const tableSql = this.quoteIdentifier(name);
    if (alias) {
      return this.raw(`${tableSql} AS ${this.quoteIdentifier(alias)}`);
    }
    return this.raw(tableSql);
  }

  column(name, alias = null) {
    const columnSql = this.quoteIdentifier(name);
    if (alias) {
      return `${columnSql} AS ${this.quoteIdentifier(alias)}`;
    }
    return columnSql;
  }

  columns(list) {
    const items = (list || []).filter(Boolean).map((item) => {
      if (isPlainObject(item) && item.kind) {
        if (item.kind === "ident") return this.quoteIdentifier(item.name);
        if (item.kind === "raw") return item.text;
      }
      return String(item);
    });
    return this.raw(items.join(", "));
  }

  star(alias = null) {
    if (!alias) return this.raw("*");
    return this.raw(`${this.quoteIdentifier(alias)}.*`);
  }

  now() {
    return this.raw(this.dialect.now());
  }

  boolean(value) {
    return this.raw(this.dialect.boolean(value));
  }

  returning(columns) {
    if (!this.dialect.supportsReturning) return this.raw("");
    if (!columns) return this.raw("");

    let columnSql = "";
    if (isPlainObject(columns) && columns.kind === "raw") {
      columnSql = columns.text;
    } else if (Array.isArray(columns)) {
      columnSql = columns.join(", ");
    } else {
      columnSql = String(columns);
    }

    if (!columnSql) return this.raw("");
    return this.raw(this.dialect.returningClause(columnSql));
  }

  limit(limit, offset) {
    return this.raw(this.dialect.limitOffset({ limit, offset }));
  }

  sql(strings, ...exprs) {
    const values = [];
    let text = strings?.[0] ?? "";

    for (let i = 0; i < exprs.length; i += 1) {
      text += this.renderToken(exprs[i], values);
      text += strings?.[i + 1] ?? "";
    }

    return { text, values };
  }

  renderToken(token, values) {
    if (token == null) return "";

    if (!isPlainObject(token) || !token.kind) {
      return String(token);
    }

    switch (token.kind) {
      case "raw":
        return token.text;
      case "ident":
        return this.quoteIdentifier(token.name);
      case "param":
        values.push(token.value);
        return this.dialect.param(values.length);
      case "list":
        if (!Array.isArray(token.values) || token.values.length === 0) {
          return "(NULL)";
        }
        return `(${token.values.map((item) => {
          values.push(item);
          return this.dialect.param(values.length);
        }).join(", ")})`;
      default:
        return "";
    }
  }

  async execute(name, query) {
    const { text, values } = query;
    if (name) {
      return this.db.query({ name, text, values });
    }
    return this.db.query({ text, values });
  }

  async executeRaw({ name, text, values }) {
    if (name) {
      return this.db.query({ name, text, values });
    }
    return this.db.query({ text, values });
  }

  cloneWithDb(db) {
    return new this.constructor({ db, dialect: this.dialect });
  }

  async withTransaction(fn) {
    if (!this.db || typeof this.db.connect !== "function") {
      return fn(this);
    }

    const client = await this.db.connect();
    const txRepo = this.cloneWithDb(client);

    try {
      await client.query("BEGIN");
      const result = await fn(txRepo);
      await client.query("COMMIT");
      return result;
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  async lockTable(tableName, mode) {
    if (!this.dialect.lockTable) return null;
    const text = this.dialect.lockTable(this.quoteIdentifier(tableName), mode);
    return this.executeRaw({
      name: `lock-${tableName}`,
      text,
      values: []
    });
  }

  async advisoryTransactionLock(lockKey, queryName = "advisory-transaction-lock") {
    return this.executeRaw({
      name: queryName,
      text: "SELECT pg_advisory_xact_lock(hashtext($1))",
      values: [String(lockKey ?? "")]
    });
  }
}