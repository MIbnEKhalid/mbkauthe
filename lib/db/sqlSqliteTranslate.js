/**
 * Best-effort translator for the small, consistent subset of Postgres SQL
 * used throughout mbkauthe's raw queries (see AuthRepository.js). This is
 * NOT a general-purpose SQL translator — it only handles the specific
 * constructs this codebase actually emits:
 *
 *   - `$1`, `$2`, ... positional params            -> `?`
 *   - `col = ANY($1)` array matching                -> `col IN (?, ?, ...)`
 *   - `NOW()`                                       -> `CURRENT_TIMESTAMP`
 *   - bare `TRUE` / `FALSE` literals                -> `1` / `0`
 *   - `::type` casts                                -> stripped
 *
 * Queries with more exotic Postgres-only syntax (INTERVAL arithmetic,
 * pg_advisory_xact_lock, LOCK TABLE, etc.) are handled by dialect-specific
 * branches in the repositories/pool instead of trying to regex them here.
 */
export function translatePgToSqlite(text, values = []) {
  let sql = String(text ?? "")
    .replace(/::\w+(\[\])?/g, "")
    .replace(/\bNOW\(\)/gi, "CURRENT_TIMESTAMP")
    .replace(/\bTRUE\b/g, "1")
    .replace(/\bFALSE\b/g, "0");

  // Queries already written in native SQLite style with `?` placeholders
  // (e.g. SqliteSessionStore) have no $N tokens to rewrite — pass their
  // values through untouched instead of rebuilding an empty array.
  if (!/\$\d/.test(sql)) {
    return { text: sql, values };
  }

  const tokenRegex = /(=\s*ANY\(\$(\d+)\))|(\$(\d+))/g;
  let out = "";
  let lastIndex = 0;
  let match;
  const newValues = [];

  while ((match = tokenRegex.exec(sql)) !== null) {
    out += sql.slice(lastIndex, match.index);

    if (match[1]) {
      // `col = ANY($N)` -> `col IN (?, ?, ...)`
      const paramIndex = Number(match[2]) - 1;
      const rawValue = values[paramIndex];
      const arr = Array.isArray(rawValue) ? rawValue : [rawValue];
      if (arr.length === 0) {
        out += "IN (NULL)"; // never matches, mirrors ANY('{}') semantics
      } else {
        out += `IN (${arr.map(() => "?").join(", ")})`;
        newValues.push(...arr);
      }
    } else if (match[3]) {
      const paramIndex = Number(match[4]) - 1;
      out += "?";
      newValues.push(values[paramIndex]);
    }

    lastIndex = tokenRegex.lastIndex;
  }

  out += sql.slice(lastIndex);
  return { text: out, values: newValues };
}
