const quoteIdentifier = (name) => `"${String(name).replace(/"/g, '""')}"`;

export const sqliteDialect = {
  name: "sqlite",
  quoteIdentifier,
  param: () => "?",
  now: () => "CURRENT_TIMESTAMP",
  boolean: (value) => (value ? "1" : "0"),
  // better-sqlite3 bundles SQLite >= 3.35, which supports RETURNING.
  supportsReturning: true,
  returningClause: (columns) => ` RETURNING ${columns}`,
  limitOffset: ({ limit, offset } = {}) => {
    const parts = [];
    if (typeof limit === "number") parts.push(`LIMIT ${limit}`);
    // SQLite requires a LIMIT clause before OFFSET; -1 means "no limit".
    if (typeof offset === "number") {
      if (!parts.length) parts.push("LIMIT -1");
      parts.push(`OFFSET ${offset}`);
    }
    return parts.length ? ` ${parts.join(" ")}` : "";
  },
  // SQLite has no table-level lock statement: writers are already serialized
  // by the file-level lock taken for the duration of a write transaction.
  lockTable: null
};
