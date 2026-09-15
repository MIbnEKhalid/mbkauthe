import { IDatabaseAdapter, IDatabaseClient, QueryOptions, QueryResult } from "./IDatabaseAdapter.js";
import { postgresDialect } from "../dialects/PostgresDialect.js";
import { IDialect } from "../dialects/IDialect.js";
import { withQueryRetry } from "../retry.js";

export class PostgresAdapter implements IDatabaseAdapter {
  public name = "postgres";
  public pool: any;
  public dialect: IDialect;

  constructor(pool: any, dialect: IDialect = postgresDialect) {
    this.pool = pool;
    this.dialect = dialect;
  }

  async query<T = any>(configOrText: string | QueryOptions, values?: any[]): Promise<QueryResult<T>> {
    return withQueryRetry(async () => {
      if (typeof configOrText === "string") {
        return this.pool.query(configOrText, values);
      }
      const config: any = { text: configOrText.text };
      if (configOrText.values !== undefined) config.values = configOrText.values;
      if (configOrText.name !== undefined) config.name = configOrText.name;
      return this.pool.query(config);
    }, { context: "PostgresAdapter" });
  }

  async connect(): Promise<IDatabaseClient> {
    return withQueryRetry(async () => {
      return this.pool.connect();
    }, { context: "PostgresAdapter:connect" });
  }

  async close(): Promise<void> {
    if (this.pool && typeof this.pool.end === "function") {
      return this.pool.end();
    }
  }

  async end(): Promise<void> {
    return this.close();
  }
}

export default PostgresAdapter;
