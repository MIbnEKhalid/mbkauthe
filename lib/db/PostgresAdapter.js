import { postgresDialect } from "./dialects/postgres.js";

/**
 * PostgreSQL database adapter wrapping a pg.Pool.
 *
 * Normalizes query execution to { text, values, name } and attaches postgresDialect.
 */
export class PostgresAdapter {
  /**
   * @param {import('pg').Pool} pool - a configured pg Pool
   * @param {object} [dialect] - dialect module (defaults to PostgreSQL)
   */
  constructor(pool, dialect = postgresDialect) {
    this.pool = pool;
    this.dialect = dialect;
  }

  /**
   * Execute a query against the pool.
   * Accepts { text, values, name } config object or (text, values).
   *
   * @param {string|{ text: string, values?: any[], name?: string }} configOrText
   * @param {any[]} [values]
   * @returns {Promise<import('pg').QueryResult>}
   */
  async query(configOrText, values) {
    if (typeof configOrText === "string") {
      return this.pool.query(configOrText, values);
    }
    const config = { text: configOrText.text };
    if (configOrText.values !== undefined) config.values = configOrText.values;
    if (configOrText.name !== undefined) config.name = configOrText.name;
    return this.pool.query(config);
  }

  /**
   * Acquire a dedicated client from the pool for transaction-scoped work.
   * Callers MUST release the returned client.
   *
   * @returns {Promise<import('pg').PoolClient>}
   */
  async connect() {
    return this.pool.connect();
  }

  /**
   * Drain and close the underlying connection pool.
   *
   * @returns {Promise<void>}
   */
  async close() {
    if (this.pool && typeof this.pool.end === "function") {
      return this.pool.end();
    }
  }

  /**
   * Alias for close() to match pg.Pool interface.
   *
   * @returns {Promise<void>}
   */
  async end() {
    return this.close();
  }
}

export default PostgresAdapter;
