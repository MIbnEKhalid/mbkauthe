import { IDialect } from '../dialects/IDialect.js';

export interface QueryResult<T = any> {
  rows: T[];
  rowCount: number;
  command?: string;
  lastInsertRowid?: number | bigint;
}

export interface QueryOptions {
  text: string;
  values?: any[];
  name?: string;
}

export interface IDatabaseClient {
  query<T = any>(queryOrText: string | QueryOptions, values?: any[]): Promise<QueryResult<T>>;
  release(): void;
}

export interface IDatabaseAdapter {
  name: string;
  dialect: IDialect;
  query<T = any>(queryOrText: string | QueryOptions, values?: any[]): Promise<QueryResult<T>>;
  connect?(): Promise<IDatabaseClient>;
  close?(): Promise<void> | void;
}
