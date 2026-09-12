import fs from "node:fs";
import path from "node:path";

/**
 * Apply a SQL schema DDL file or raw SQL string to an adapter or pool.
 */
export async function applySchema(adapterOrPool, schemaPathOrSql, options = {}) {
  const { silent = false, name = "" } = options;

  let sql = schemaPathOrSql;
  let source = name || "sql string";

  if (typeof schemaPathOrSql === "string") {
    const isFile = schemaPathOrSql.endsWith(".sql") || (schemaPathOrSql.length < 500 && fs.existsSync(schemaPathOrSql));
    if (isFile) {
      const resolved = path.resolve(schemaPathOrSql);
      source = name || path.basename(resolved);
      sql = fs.readFileSync(resolved, "utf-8");
    }
  }

  const trimmed = (sql || "").trim();
  if (!trimmed) return { success: true };

  try {
    if (typeof adapterOrPool.exec === "function") {
      adapterOrPool.exec(trimmed);
    } else if (typeof adapterOrPool.query === "function") {
      await adapterOrPool.query(trimmed);
    } else {
      throw new Error("Invalid adapterOrPool: missing query() or exec() method");
    }
    if (!silent) console.log(`[schema] Successfully applied schema (${source})`);
    return { success: true };
  } catch (err) {
    if (!silent) console.error(`[schema] Failed to apply schema (${source}):`, err.message);
    throw err;
  }
}

export default applySchema;
