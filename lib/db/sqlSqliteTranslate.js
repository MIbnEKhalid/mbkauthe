/**
 * Best-effort translator from PostgreSQL SQL to SQLite-compatible SQL.
 * Supports the complete subset of PostgreSQL syntax used across mbktech apps:
 *   1. `::type` casts                     → removed
 *   2. `ILIKE`                            → `LIKE`
 *   3. `NOW() AT TIME ZONE 'UTC'`         → `CURRENT_TIMESTAMP`
 *   4. `NOW()`                            → `CURRENT_TIMESTAMP`
 *   5. bare `TRUE` / `FALSE`              → `1` / `0`
 *   6. `BTRIM`                            → `TRIM`
 *   7. `jsonb_typeof(...)`                → `JSON_TYPE(...)`
 *   8. `jsonb_array_length(...)`          → `JSON_ARRAY_LENGTH(...)`
 *   9. `COUNT(*) FILTER (WHERE ...)`      → `SUM(CASE WHEN ... THEN 1 ELSE 0 END)`
 *  10. `NULLS FIRST` / `NULLS LAST`       → removed
 *  11. `to_char(expr, format)`            → `strftime(format_replacement, expr)`
 *  12. `gen_random_uuid()`                → replacement hex UUID via SQLite functions
 *  13. `$N` positional params             → `?`
 *  14. `col = ANY($N)`                    → `col IN (?, ?, ...)`
 */

function toCharFormatToStrftime(pgFormat) {
  const fmt = pgFormat.replace(/^'|'$/g, "");
  const literals = [];
  const withoutLiterals = fmt.replace(/"([^"]*)"/g, (match, lit) => {
    literals.push(lit);
    return `\x00LIT${literals.length - 1}\x00`;
  });

  let sqliteFmt = withoutLiterals
    .replace(/YYYY/g, "%Y")
    .replace(/MM/g, "%m")
    .replace(/DD/g, "%d")
    .replace(/HH24/g, "%H")
    .replace(/MI/g, "%M")
    .replace(/SS/g, "%S");

  sqliteFmt = sqliteFmt.replace(/\x00LIT(\d+)\x00/g, (match, idx) => literals[parseInt(idx, 10)]);
  return sqliteFmt;
}

export function translatePgToSqlite(text, values = []) {
  let sql = String(text ?? "");

  // 1. Remove ::type casts (e.g. ::jsonb, ::int, ::text, ::varchar(255), ::text[])
  sql = sql.replace(/::\w+(?:\s*\([^)]*\))?(?:\s*\[\])?/g, "");

  // 2. ILIKE → LIKE
  sql = sql.replace(/\bILIKE\b/gi, "LIKE");

  // 3. NOW() AT TIME ZONE 'UTC' → CURRENT_TIMESTAMP
  sql = sql.replace(/\bNOW\(\)\s+AT\s+TIME\s+ZONE\s+'[^']*'/gi, "CURRENT_TIMESTAMP");

  // 4. NOW() → CURRENT_TIMESTAMP
  sql = sql.replace(/\bNOW\(\)/gi, "CURRENT_TIMESTAMP");

  // 5. Bare TRUE / FALSE → 1 / 0
  sql = sql.replace(/\bTRUE\b/g, "1");
  sql = sql.replace(/\bFALSE\b/g, "0");

  // 6. BTRIM → TRIM
  sql = sql.replace(/\bBTRIM\s*\(/gi, "TRIM(");

  // 7. jsonb_typeof(...) → JSON_TYPE(...)
  sql = sql.replace(/\bjsonb_typeof\s*\(/gi, "JSON_TYPE(");

  // 8. jsonb_array_length(...) → JSON_ARRAY_LENGTH(...)
  sql = sql.replace(/\bjsonb_array_length\s*\(/gi, "JSON_ARRAY_LENGTH(");

  // 9. COUNT(*) FILTER (WHERE condition) → SUM(CASE WHEN condition THEN 1 ELSE 0 END)
  const FILTER_RE = /COUNT\s*\(\s*\*\s*\)\s+FILTER\s*\(WHERE\s+/gi;
  let filterMatch;
  while ((filterMatch = FILTER_RE.exec(sql)) !== null) {
    const matchStart = filterMatch.index;
    const afterWhere = matchStart + filterMatch[0].length;

    let depth = 1;
    let endIdx = afterWhere;
    let inString = false;
    let stringChar = null;

    for (let i = afterWhere; i < sql.length; i++) {
      const ch = sql[i];
      if (inString) {
        if (ch === stringChar && sql[i - 1] !== "\\") {
          inString = false;
        }
        continue;
      }
      if (ch === "'" || ch === '"') {
        inString = true;
        stringChar = ch;
        continue;
      }
      if (ch === "(") depth++;
      if (ch === ")") {
        depth--;
        if (depth === 0) {
          endIdx = i;
          break;
        }
      }
    }

    const condition = sql.slice(afterWhere, endIdx).trim();
    const replacement = `SUM(CASE WHEN ${condition} THEN 1 ELSE 0 END)`;
    sql = sql.slice(0, matchStart) + replacement + sql.slice(endIdx + 1);
    FILTER_RE.lastIndex = matchStart + replacement.length;
  }

  // 10. Remove NULLS FIRST / NULLS LAST
  sql = sql.replace(/\bNULLS\s+(FIRST|LAST)\b/gi, "");

  // 11. to_char(expr, format) → strftime(format, expr)
  sql = sql.replace(
    /\bto_char\s*\(\s*([^,]+)\s*,\s*'([^']+)'\s*\)/gi,
    (match, expr, format) => {
      const strfmt = toCharFormatToStrftime(`'${format}'`);
      return `strftime('${strfmt}', ${expr})`;
    }
  );

  // 12. gen_random_uuid() → SQLite hex-based UUID v4
  sql = sql.replace(
    /\bgen_random_uuid\s*\(\s*\)/gi,
    "(lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' || substr(lower(hex(randomblob(3))),2) || '-' || printf('%x', (random() % 4 + 8)) || substr(lower(hex(randomblob(3))),2) || '-' || lower(hex(randomblob(6))))"
  );

  // 13. SERIAL PRIMARY KEY → INTEGER PRIMARY KEY AUTOINCREMENT
  sql = sql.replace(/\bSERIAL\s+PRIMARY\s+KEY\b/gi, "INTEGER PRIMARY KEY AUTOINCREMENT");

  // 14. STRING_AGG → SQLite group_concat / replace
  sql = sql.replace(
    /\bSTRING_AGG\s*\(\s*DISTINCT\s+([^,]+)\s*,\s*('([^']*)'|"([^"]*)")\s*\)/gi,
    (match, expr, quotedSep, sepSingle, sepDouble) => {
      const sep = sepSingle !== undefined ? sepSingle : sepDouble;
      return `replace(group_concat(DISTINCT ${expr}), ',', '${sep}')`;
    }
  );
  sql = sql.replace(
    /\bSTRING_AGG\s*\(\s*([^,]+)\s*,\s*('([^']*)'|"([^"]*)")\s*\)/gi,
    (match, expr, quotedSep, sepSingle, sepDouble) => {
      const sep = sepSingle !== undefined ? sepSingle : sepDouble;
      return `group_concat(${expr}, '${sep}')`;
    }
  );

  // 15. ARRAY_AGG → SQLite json_group_array
  sql = sql.replace(/\bARRAY_AGG\s*\(\s*DISTINCT\s+([^)]+)\s*\)/gi, "json_group_array(DISTINCT $1)");
  sql = sql.replace(/\bARRAY_AGG\s*\(\s*([^)]+)\s*\)/gi, "json_group_array($1)");

  // 16. Strip FOR UPDATE / FOR SHARE
  sql = sql.replace(/\bFOR\s+(UPDATE|SHARE)(\s+NOWAIT|\s+SKIP\s+LOCKED)?\b/gi, "");

  // 17. EXTRACT(field FROM expr) → SQLite strftime integer
  sql = sql.replace(
    /\bEXTRACT\s*\(\s*(\w+)\s+FROM\s+([^)]+)\s*\)/gi,
    (match, field, expr) => {
      const f = field.toUpperCase();
      if (f === "HOUR") return `CAST(strftime('%H', ${expr}) AS INTEGER)`;
      if (f === "DAY") return `CAST(strftime('%d', ${expr}) AS INTEGER)`;
      if (f === "MONTH") return `CAST(strftime('%m', ${expr}) AS INTEGER)`;
      if (f === "YEAR") return `CAST(strftime('%Y', ${expr}) AS INTEGER)`;
      if (f === "EPOCH") return `CAST(strftime('%s', ${expr}) AS INTEGER)`;
      if (f === "MINUTE") return `CAST(strftime('%M', ${expr}) AS INTEGER)`;
      if (f === "SECOND") return `CAST(strftime('%S', ${expr}) AS INTEGER)`;
      return match;
    }
  );

  if (!/\$\d/.test(sql)) return { text: sql, values };

  // 16 & 17. $N → ? and = ANY($N) → IN (?, ?, ...)
  const tokenRegex = /(=\s*ANY\(\$(\d+)\))|(\$(\d+))/g;
  let out = "";
  let lastIndex = 0;
  let match;
  const newValues = [];

  while ((match = tokenRegex.exec(sql)) !== null) {
    out += sql.slice(lastIndex, match.index);

    if (match[1]) {
      const raw = values[Number(match[2]) - 1];
      const arr = Array.isArray(raw) ? raw : [raw];
      out += arr.length === 0 ? "IN (NULL)" : `IN (${arr.map(() => "?").join(", ")})`;
      newValues.push(...arr);
    } else if (match[3]) {
      out += "?";
      newValues.push(values[Number(match[4]) - 1]);
    }

    lastIndex = tokenRegex.lastIndex;
  }

  return { text: out + sql.slice(lastIndex), values: newValues };
}

export default translatePgToSqlite;
