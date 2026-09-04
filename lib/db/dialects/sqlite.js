const quoteIdentifier = (name) => `"${String(name).replace(/"/g, '""')}"`;

export const sqliteDialect = {
  name: "sqlite",
  quoteIdentifier,
  param: () => "?",
  now: () => "CURRENT_TIMESTAMP",
  boolean: (value) => (value ? "1" : "0"),
  supportsReturning: true,
  returningClause: (columns) => ` RETURNING ${columns}`,
  limitOffset: ({ limit, offset } = {}) => {
    const hasLimit = typeof limit === "number";
    const hasOffset = typeof offset === "number";
    if (!hasLimit && !hasOffset) return "";
    return ` ${hasLimit ? `LIMIT ${limit}` : "LIMIT -1"}${hasOffset ? ` OFFSET ${offset}` : ""}`;
  },
  lockTable: null
};
