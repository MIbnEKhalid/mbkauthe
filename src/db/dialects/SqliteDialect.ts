import { IDialect } from './IDialect.js';

const quoteIdentifier = (name: string): string => `"${String(name).replace(/"/g, '""')}"`;

export const sqliteDialect: IDialect = {
  name: "sqlite",
  quoteIdentifier,
  param: () => "?",
  now: () => "CURRENT_TIMESTAMP",
  boolean: (value: boolean | string | number) => (value && value !== 'false' && value !== 'f' && value !== '0' ? "1" : "0"),
  supportsReturning: true,
  supportsAdvisoryLocks: false,
  returningClause: (columns: string) => ` RETURNING ${columns}`,
  limitOffset: ({ limit, offset } = {}) => {
    const hasLimit = limit !== undefined && limit !== null;
    const hasOffset = offset !== undefined && offset !== null;
    return !hasLimit && !hasOffset ? "" : ` ${hasLimit ? `LIMIT ${limit}` : "LIMIT -1"}${hasOffset ? ` OFFSET ${offset}` : ""}`;
  },
  lockTable: undefined,
};

export default sqliteDialect;
