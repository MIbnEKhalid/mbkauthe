const quoteIdentifier = (name) => `"${String(name).replace(/"/g, '""')}"`;

export const postgresDialect = {
  name: "postgres",
  quoteIdentifier,
  param: (index) => `$${index}`,
  now: () => "NOW()",
  boolean: (value) => (value ? "TRUE" : "FALSE"),
  supportsReturning: true,
  returningClause: (columns) => ` RETURNING ${columns}`,
  limitOffset: ({ limit, offset } = {}) => {
    const parts = [];
    if (typeof limit === "number") parts.push(`LIMIT ${limit}`);
    if (typeof offset === "number") parts.push(`OFFSET ${offset}`);
    return parts.length ? ` ${parts.join(" ")}` : "";
  },
  lockTable: (tableSql, mode = "ROW EXCLUSIVE") => `LOCK TABLE ${tableSql} IN ${mode} MODE`
};