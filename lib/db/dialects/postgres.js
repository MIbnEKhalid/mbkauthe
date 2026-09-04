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
    const parts = [typeof limit === "number" && `LIMIT ${limit}`, typeof offset === "number" && `OFFSET ${offset}`].filter(Boolean);
    return parts.length ? ` ${parts.join(" ")}` : "";
  },
  lockTable: (tableSql, mode = "ROW EXCLUSIVE") => `LOCK TABLE ${tableSql} IN ${mode} MODE`
};