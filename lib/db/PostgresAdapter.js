import { postgresDialect } from "./dialects/postgres.js";
import { withQueryRetry } from "./retry.js";

/**
 * PostgreSQL database adapter wrapping a pg.Pool.
 */
export class PostgresAdapter {
  constructor(pool, dialect = postgresDialect) {
    this.pool = pool;
    this.dialect = dialect;
  }

  async query(configOrText, values) {
    return withQueryRetry(async () => {
      if (typeof configOrText === "string") {
        return this.pool.query(configOrText, values);
      }
      const config = { text: configOrText.text };
      if (configOrText.values !== undefined) config.values = configOrText.values;
      if (configOrText.name !== undefined) config.name = configOrText.name;
      return this.pool.query(config);
    }, { context: "PostgresAdapter" });
  }

  async connect() {
    return withQueryRetry(async () => {
      return this.pool.connect();
    }, { context: "PostgresAdapter:connect" });
  }

  async close() {
    if (this.pool && typeof this.pool.end === "function") {
      return this.pool.end();
    }
  }

  async end() {
    return this.close();
  }
}

export default PostgresAdapter;
