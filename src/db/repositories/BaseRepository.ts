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

export class BaseRepository<TEntity = any, TCreateInput = Partial<TEntity>, TUpdateInput = Partial<TEntity>> {
  public db: any;
  public adapter: any;
  public dialect: IDialect;
  public defaultTable: string | null = null;

  constructor(adapterOrOptions: any = {}) {
    if (adapterOrOptions && typeof adapterOrOptions.query === "function") {
      this.db = adapterOrOptions;
      this.adapter = adapterOrOptions;
      this.dialect = adapterOrOptions.dialect || defaultDialect || postgresDialect;
    } else {
      this.db = adapterOrOptions?.db || adapterOrOptions?.adapter || dblogin;
      this.adapter = this.db;
      this.dialect = adapterOrOptions?.dialect || this.db?.dialect || defaultDialect || postgresDialect;
      this.defaultTable = adapterOrOptions?.defaultTable || adapterOrOptions?.tableName || null;
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

  limit(limit: any, offset: any = null) {
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

  /**
   * Find a single record by ID
   */
  async findById(id: string | number, idColumn: string = "id", tableName?: string): Promise<TEntity | null> {
    const table = tableName || this.defaultTable;
    if (!table) throw new Error("[BaseRepository] Table name must be specified or configured as defaultTable");
    const query = this.sql`SELECT * FROM ${this.table(table)} WHERE ${this.ident(idColumn)} = ${this.value(id)} ${this.limit(1, 0)}`;
    const result = await this.execute<TEntity>(query);
    return result.rows[0] || null;
  }

  /**
   * Find a single record matching specific criteria
   */
  async findOne(criteria: Partial<TEntity> | Record<string, any>, tableName?: string): Promise<TEntity | null> {
    const table = tableName || this.defaultTable;
    if (!table) throw new Error("[BaseRepository] Table name must be specified or configured as defaultTable");
    const entries = Object.entries(criteria).filter(([_, v]) => v !== undefined);
    if (entries.length === 0) {
      const query = this.sql`SELECT * FROM ${this.table(table)} ${this.limit(1, 0)}`;
      const result = await this.execute<TEntity>(query);
      return result.rows[0] || null;
    }

    const values: any[] = [];
    let sqlText = `SELECT * FROM ${this.quoteIdentifier(table)} WHERE `;
    entries.forEach(([k, v], idx) => {
      if (idx > 0) sqlText += " AND ";
      sqlText += `${this.quoteIdentifier(k)} = ${this.dialect.param(values.length + 1)}`;
      values.push(v);
    });
    sqlText += ` ${this.dialect.limitOffset({ limit: 1 })}`;
    const result = await this.execute<TEntity>({ text: sqlText, values });
    return result.rows[0] || null;
  }

  /**
   * Find multiple records matching specific criteria
   */
  async findMany(
    criteria: Partial<TEntity> | Record<string, any> = {},
    options: { tableName?: string; limit?: number; offset?: number; orderBy?: string } = {}
  ): Promise<TEntity[]> {
    const table = options.tableName || this.defaultTable;
    if (!table) throw new Error("[BaseRepository] Table name must be specified or configured as defaultTable");
    const entries = Object.entries(criteria).filter(([_, v]) => v !== undefined);
    const values: any[] = [];
    let sqlText = `SELECT * FROM ${this.quoteIdentifier(table)}`;

    if (entries.length > 0) {
      sqlText += " WHERE ";
      entries.forEach(([k, v], idx) => {
        if (idx > 0) sqlText += " AND ";
        sqlText += `${this.quoteIdentifier(k)} = ${this.dialect.param(values.length + 1)}`;
        values.push(v);
      });
    }

    if (options.orderBy) {
      sqlText += ` ORDER BY ${options.orderBy}`;
    }

    if (options.limit !== undefined || options.offset !== undefined) {
      sqlText += ` ${this.dialect.limitOffset({ limit: options.limit, offset: options.offset })}`;
    }

    const result = await this.execute<TEntity>({ text: sqlText, values });
    return result.rows;
  }

  /**
   * Count records matching specific criteria
   */
  async count(criteria: Partial<TEntity> | Record<string, any> = {}, tableName?: string): Promise<number> {
    const table = tableName || this.defaultTable;
    if (!table) throw new Error("[BaseRepository] Table name must be specified or configured as defaultTable");
    const entries = Object.entries(criteria).filter(([_, v]) => v !== undefined);
    const values: any[] = [];
    let sqlText = `SELECT COUNT(*) as total FROM ${this.quoteIdentifier(table)}`;

    if (entries.length > 0) {
      sqlText += " WHERE ";
      entries.forEach(([k, v], idx) => {
        if (idx > 0) sqlText += " AND ";
        sqlText += `${this.quoteIdentifier(k)} = ${this.dialect.param(values.length + 1)}`;
        values.push(v);
      });
    }

    const result = await this.execute<{ total: number | string }>({ text: sqlText, values });
    const countVal = result.rows[0]?.total;
    return typeof countVal === "number" ? countVal : parseInt(String(countVal || 0), 10);
  }

  /**
   * Insert a new record
   */
  async create(data: TCreateInput, tableName?: string): Promise<TEntity> {
    const table = tableName || this.defaultTable;
    if (!table) throw new Error("[BaseRepository] Table name must be specified or configured as defaultTable");
    const entries = Object.entries(data as Record<string, any>).filter(([_, v]) => v !== undefined);
    if (entries.length === 0) {
      throw new Error("[BaseRepository] Cannot create record with empty data");
    }

    const columns = entries.map(([k]) => this.quoteIdentifier(k)).join(", ");
    const values: any[] = [];
    const params = entries.map(([_, v]) => {
      values.push(v);
      return this.dialect.param(values.length);
    }).join(", ");

    const returningClause = this.dialect.supportsReturning ? ` ${this.dialect.returningClause("*")}` : "";
    const sqlText = `INSERT INTO ${this.quoteIdentifier(table)} (${columns}) VALUES (${params})${returningClause}`;
    const result = await this.execute<TEntity>({ text: sqlText, values });

    if (result.rows && result.rows.length > 0) {
      return result.rows[0];
    }
    if (result.lastInsertRowid) {
      const inserted = await this.findById(result.lastInsertRowid as any, "id", table);
      if (inserted) return inserted;
    }
    return data as any;
  }

  /**
   * Update a record by ID
   */
  async updateById(
    id: string | number,
    data: TUpdateInput,
    options: { idColumn?: string; tableName?: string } = {}
  ): Promise<TEntity | null> {
    const table = options.tableName || this.defaultTable;
    const idColumn = options.idColumn || "id";
    if (!table) throw new Error("[BaseRepository] Table name must be specified or configured as defaultTable");
    const entries = Object.entries(data as Record<string, any>).filter(([_, v]) => v !== undefined);
    if (entries.length === 0) return this.findById(id, idColumn, table);

    const values: any[] = [];
    const setClauses = entries.map(([k, v]) => {
      values.push(v);
      return `${this.quoteIdentifier(k)} = ${this.dialect.param(values.length)}`;
    }).join(", ");

    values.push(id);
    const idParam = this.dialect.param(values.length);
    const returningClause = this.dialect.supportsReturning ? ` ${this.dialect.returningClause("*")}` : "";
    const sqlText = `UPDATE ${this.quoteIdentifier(table)} SET ${setClauses} WHERE ${this.quoteIdentifier(idColumn)} = ${idParam}${returningClause}`;

    const result = await this.execute<TEntity>({ text: sqlText, values });
    if (result.rows && result.rows.length > 0) {
      return result.rows[0];
    }
    return this.findById(id, idColumn, table);
  }

  /**
   * Delete a record by ID
   */
  async deleteById(id: string | number, idColumn: string = "id", tableName?: string): Promise<boolean> {
    const table = tableName || this.defaultTable;
    if (!table) throw new Error("[BaseRepository] Table name must be specified or configured as defaultTable");
    const query = this.sql`DELETE FROM ${this.table(table)} WHERE ${this.ident(idColumn)} = ${this.value(id)}`;
    const result = await this.execute(query);
    return (result.rowCount ?? 0) > 0;
  }

  cloneWithDb(db: any) {
    const instance = Object.create(Object.getPrototypeOf(this));
    Object.assign(instance, this);
    instance.db = db;
    instance.adapter = db;
    instance.dialect = db?.dialect || this.dialect;
    instance.defaultTable = this.defaultTable;
    return instance;
  }

  cloneWithAdapter(adapter: any) {
    const instance = Object.create(Object.getPrototypeOf(this));
    Object.assign(instance, this);
    instance.db = adapter;
    instance.adapter = adapter;
    instance.dialect = adapter?.dialect || this.dialect;
    instance.defaultTable = this.defaultTable;
    return instance;
  }

  async withTransaction<R = any>(fn: (txRepo: this, client: any) => Promise<R>): Promise<R> {
    if (this.db?._inTransaction) {
      return fn(this, this.db);
    }

    if (!this.db || typeof this.db.connect !== "function") {
      return fn(this, this.db);
    }

    const client = await this.db.connect();
    client._inTransaction = true;
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
      client._inTransaction = false;
      if (typeof client.release === "function") {
        client.release();
      }
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
