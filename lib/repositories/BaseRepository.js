/**
 * MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

import { postgresDialect } from "../db/dialects/postgres.js";

const isPlainObject = (val) => Boolean(val && typeof val === "object" && !Array.isArray(val));

export class BaseRepository {
  constructor(adapterOrOptions = {}) {
    if (adapterOrOptions && typeof adapterOrOptions.query === "function") {
      this.db = adapterOrOptions;
      this.adapter = adapterOrOptions;
      this.dialect = adapterOrOptions.dialect || postgresDialect;
    } else {
      this.db = adapterOrOptions?.db || adapterOrOptions?.adapter || null;
      this.adapter = this.db;
      this.dialect = adapterOrOptions?.dialect || this.db?.dialect || postgresDialect;
    }
  }

  setDb(db, dialect = null) {
    this.db = db;
    this.adapter = db;
    this.dialect = dialect || db?.dialect || this.dialect;
  }

  quoteIdentifier(name) {
    if (name === "*") return "*";
    return String(name).split(".").map((part) => (part === "*" ? "*" : this.dialect.quoteIdentifier(part))).join(".");
  }

  ident(name) { return { kind: "ident", name }; }
  value(val) { return { kind: "param", value: val }; }
  raw(text) { return { kind: "raw", text: text ?? "" }; }
  list(values) { return { kind: "list", values }; }

  table(name, alias = null) {
    const tableSql = this.quoteIdentifier(name);
    return this.raw(alias ? `${tableSql} AS ${this.quoteIdentifier(alias)}` : tableSql);
  }

  column(name, alias = null) {
    const columnSql = this.quoteIdentifier(name);
    return alias ? `${columnSql} AS ${this.quoteIdentifier(alias)}` : columnSql;
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
    return this.raw(alias ? `${this.quoteIdentifier(alias)}.*` : "*");
  }

  now() { return this.raw(this.dialect.now()); }
  boolean(value) { return this.raw(this.dialect.boolean(value)); }

  returning(columns) {
    if (!this.dialect.supportsReturning || !columns) return this.raw("");
    const columnSql = isPlainObject(columns) && columns.kind === "raw"
      ? columns.text
      : Array.isArray(columns) ? columns.join(", ") : String(columns);
    return columnSql ? this.raw(this.dialect.returningClause(columnSql)) : this.raw("");
  }

  limit(limit, offset) {
    return this.raw(this.dialect.limitOffset({ limit, offset }));
  }

  sql(strings, ...exprs) {
    const values = [];
    let text = strings?.[0] ?? "";
    for (let i = 0; i < exprs.length; i += 1) {
      text += this.renderToken(exprs[i], values) + (strings?.[i + 1] ?? "");
    }
    return { text, values };
  }

  renderToken(token, values) {
    if (token == null) return "";
    if (!isPlainObject(token) || !token.kind) return String(token);

    switch (token.kind) {
      case "raw":
        return token.text;
      case "ident":
        return this.quoteIdentifier(token.name);
      case "param":
        values.push(token.value);
        return this.dialect.param(values.length);
      case "list":
        if (!Array.isArray(token.values) || token.values.length === 0) return "(NULL)";
        return `(${token.values.map((item) => {
          values.push(item);
          return this.dialect.param(values.length);
        }).join(", ")})`;
      default:
        return "";
    }
  }

  async execute(queryOrTextOrName, valuesOrQuery = [], executorOrName = this.db, name) {
    if (typeof queryOrTextOrName === "string" && typeof valuesOrQuery === "object" && valuesOrQuery !== null && !Array.isArray(valuesOrQuery) && ("text" in valuesOrQuery)) {
      return this.executeRaw({ name: queryOrTextOrName, ...valuesOrQuery });
    }

    if (typeof queryOrTextOrName === "object" && queryOrTextOrName !== null) {
      const config = { ...queryOrTextOrName };
      const exec = (valuesOrQuery && typeof valuesOrQuery.query === "function")
        ? valuesOrQuery
        : (executorOrName && typeof executorOrName.query === "function" ? executorOrName : this.db);
      return exec.query(config);
    }

    let executor = executorOrName;
    let stmtName = name;
    if (typeof executorOrName === "string") {
      stmtName = executorOrName;
      executor = this.db;
    } else if (!executor || typeof executor.query !== "function") {
      executor = this.db;
    }

    const values = Array.isArray(valuesOrQuery) ? valuesOrQuery : [];
    return stmtName ? executor.query({ text: queryOrTextOrName, values, name: stmtName }) : executor.query(queryOrTextOrName, values);
  }

  async query(text, values = []) {
    return this.execute(text, values);
  }

  async executeRaw({ name, text, values = [] }, executor = this.db) {
    const target = (executor && typeof executor.query === "function") ? executor : this.db;
    return target.query(name ? { name, text, values } : { text, values });
  }

  cloneWithDb(db) {
    return new this.constructor({ db, dialect: this.dialect });
  }

  cloneWithAdapter(adapter) {
    return new this.constructor(adapter);
  }

  async withTransaction(fn) {
    if (!this.db || typeof this.db.connect !== "function") return fn(this);

    const client = await this.db.connect();
    const txRepo = this.cloneWithDb(client);
    try {
      await client.query("BEGIN");
      const result = await fn(txRepo, client);
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
    return this.executeRaw({
      name: `lock-${tableName}`,
      text: this.dialect.lockTable(this.quoteIdentifier(tableName), mode),
      values: []
    });
  }

  async advisoryTransactionLock(lockKey, queryName = "advisory-transaction-lock") {
    if (this.dialect.name !== "postgres") return null;
    return this.executeRaw({
      name: queryName,
      text: "SELECT pg_advisory_xact_lock(hashtext($1))",
      values: [String(lockKey ?? "")]
    });
  }
}