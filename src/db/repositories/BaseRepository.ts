import { IDialect } from "../dialects/IDialect.js";
import { postgresDialect } from "../dialects/PostgresDialect.js";
import { IDatabaseAdapter, QueryResult } from "../adapters/IDatabaseAdapter.js";
import { dblogin, dialect as defaultDialect } from "../pool.js";

export interface BaseRepositoryOptions {
  db?: any;
  adapter?: any;
  dialect?: IDialect;
}

const isPlainObject = (val: any) => Boolean(val && typeof val === "object" && !Array.isArray(val));

export class BaseRepository {
  public db: any;
  public adapter: any;
  public dialect: IDialect;

  constructor(adapterOrOptions: any = {}) {
    if (adapterOrOptions && typeof adapterOrOptions.query === "function") {
      this.db = adapterOrOptions;
      this.adapter = adapterOrOptions;
      this.dialect = adapterOrOptions.dialect || defaultDialect || postgresDialect;
    } else {
      this.db = adapterOrOptions?.db || adapterOrOptions?.adapter || dblogin;
      this.adapter = this.db;
      this.dialect = adapterOrOptions?.dialect || this.db?.dialect || defaultDialect || postgresDialect;
    }
  }

  setDb(db: any, dialect: IDialect | null = null): void {
    this.db = db;
    this.adapter = db;
    this.dialect = dialect || db?.dialect || this.dialect;
  }

  quoteIdentifier(name: string): string {
    if (name === "*") return "*";
    return String(name).split(".").map((part) => (part === "*" ? "*" : this.dialect.quoteIdentifier(part))).join(".");
  }

  ident(name: string) { return { kind: "ident", name }; }
  value(val: any) { return { kind: "param", value: val }; }
  raw(text: any) { return { kind: "raw", text: text ?? "" }; }
  list(values: any[]) { return { kind: "list", values }; }

  table(name: string, alias: string | null = null) {
    const tableSql = this.quoteIdentifier(name);
    return this.raw(alias ? `${tableSql} AS ${this.quoteIdentifier(alias)}` : tableSql);
  }

  column(name: string, alias: string | null = null) {
    const columnSql = this.quoteIdentifier(name);
    return alias ? `${columnSql} AS ${this.quoteIdentifier(alias)}` : columnSql;
  }

  columns(list: any[]) {
    const items = (list || []).filter(Boolean).map((item) => {
      if (isPlainObject(item) && item.kind) {
        if (item.kind === "ident") return this.quoteIdentifier(item.name);
        if (item.kind === "raw") return item.text;
      }
      return String(item);
    });
    return this.raw(items.join(", "));
  }

  star(alias: string | null = null) {
    return this.raw(alias ? `${this.quoteIdentifier(alias)}.*` : "*");
  }

  now() { return this.raw(this.dialect.now()); }
  boolean(value: boolean | string | number) { return this.raw(this.dialect.boolean(value)); }

  returning(columns: any) {
    if (!this.dialect.supportsReturning || !columns) return this.raw("");
    const columnSql = isPlainObject(columns) && columns.kind === "raw"
      ? columns.text
      : Array.isArray(columns) ? columns.join(", ") : String(columns);
    return columnSql ? this.raw(this.dialect.returningClause(columnSql)) : this.raw("");
  }

  limit(limit: any, offset: any) {
    return this.raw(this.dialect.limitOffset({ limit, offset }));
  }

  sql(strings: TemplateStringsArray | string[], ...exprs: any[]) {
    const values: any[] = [];
    let text = strings?.[0] ?? "";
    for (let i = 0; i < exprs.length; i += 1) {
      text += this.renderToken(exprs[i], values) + (strings?.[i + 1] ?? "");
    }
    return { text, values };
  }

  renderToken(token: any, values: any[]): string {
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
        return `(${token.values.map((item: any) => {
          values.push(item);
          return this.dialect.param(values.length);
        }).join(", ")})`;
      default:
        return "";
    }
  }

  async execute<T = any>(queryOrTextOrName: any, valuesOrQuery: any = [], executorOrName: any = this.db, name?: string): Promise<QueryResult<T>> {
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

  async query<T = any>(text: any, values: any[] = []): Promise<QueryResult<T>> {
    return this.execute<T>(text, values);
  }

  async executeRaw<T = any>({ name, text, values = [] }: { name?: string; text: string; values?: any[] }, executor: any = this.db): Promise<QueryResult<T>> {
    const target = (executor && typeof executor.query === "function") ? executor : this.db;
    return target.query(name ? { name, text, values } : { text, values });
  }

  cloneWithDb(db: any) {
    return new (this.constructor as any)({ db, dialect: this.dialect });
  }

  cloneWithAdapter(adapter: any) {
    return new (this.constructor as any)(adapter);
  }

  async withTransaction<R = any>(fn: (txRepo: this, client: any) => Promise<R>): Promise<R> {
    if (!this.db || typeof this.db.connect !== "function") return fn(this, this.db);

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

  async lockTable(tableName: string, mode: string = "ROW EXCLUSIVE") {
    if (!this.dialect.lockTable) return null;
    return this.executeRaw({
      name: `lock-${tableName}`,
      text: this.dialect.lockTable(this.quoteIdentifier(tableName), mode),
      values: []
    });
  }

  async advisoryTransactionLock(lockKey: string, queryName: string = "advisory-transaction-lock") {
    if (this.dialect.name !== "postgres") return null;
    return this.executeRaw({
      name: queryName,
      text: "SELECT pg_advisory_xact_lock(hashtext($1))",
      values: [String(lockKey ?? "")]
    });
  }
}

export default BaseRepository;
