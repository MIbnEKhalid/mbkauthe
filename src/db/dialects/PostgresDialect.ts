import { IDialect } from './IDialect.js';

const quoteIdentifier = (name: string): string => `"${String(name).replace(/"/g, '""')}"`;

export const postgresDialect: IDialect = {
  name: "postgres",
  quoteIdentifier,
  param: (index: number) => `$${index}`,
  now: () => "NOW()",
  boolean: (value: boolean | string | number) => (value && value !== 'false' && value !== 'f' && value !== '0' ? "TRUE" : "FALSE"),
  supportsReturning: true,
  supportsAdvisoryLocks: true,
  returningClause: (columns: string) => ` RETURNING ${columns}`,
  limitOffset: ({ limit, offset } = {}) => {
    const parts = [
      limit !== undefined && limit !== null && `LIMIT ${limit}`,
      offset !== undefined && offset !== null && `OFFSET ${offset}`
    ].filter(Boolean);
    return parts.length ? ` ${parts.join(" ")}` : "";
  },
  lockTable: (tableSql: string, mode: string = "ROW EXCLUSIVE") => `LOCK TABLE ${tableSql} IN ${mode} MODE`,
};

export default postgresDialect;
