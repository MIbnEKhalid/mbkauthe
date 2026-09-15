export interface IDialect {
  name: 'postgres' | 'sqlite' | string;
  supportsReturning: boolean;
  supportsAdvisoryLocks: boolean;
  param(index: number): string;
  quoteIdentifier(identifier: string): string;
  now(): string;
  boolean(value: boolean | string | number): string;
  returningClause(columns: string): string;
  limitOffset(options: { limit?: number | string; offset?: number | string }): string;
  lockTable?(tableName: string, mode?: string): string;
  inArrayClause?(column: string, paramIndex: number, length?: number): string;
}
