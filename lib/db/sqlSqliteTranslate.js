/**
 * Best-effort translator from PostgreSQL SQL to SQLite-compatible SQL.
 */

function toCharFormatToStrftime(pgFormat) {
  const literals = [];
  const withoutLiterals = pgFormat.replace(/^'|'$/g, "").replace(/"([^"]*)"/g, (_, lit) => {
    literals.push(lit);
    return `\x00LIT${literals.length - 1}\x00`;
  });

  return withoutLiterals
    .replace(/YYYY/g, "%Y")
    .replace(/MM/g, "%m")
    .replace(/DD/g, "%d")
    .replace(/HH24/g, "%H")
    .replace(/MI/g, "%M")
    .replace(/SS/g, "%S")
    .replace(/\x00LIT(\d+)\x00/g, (_, idx) => literals[parseInt(idx, 10)]);
}

export function translatePgToSqlite(text, values = []) {
  let sql = String(text ?? "");

  sql = sql
    .replace(/::\w+(?:\s*\([^)]*\))?(?:\s*\[\])?/g, "")
    .replace(/\bILIKE\b/gi, "LIKE")
    .replace(/\bNOW\(\)\s+AT\s+TIME\s+ZONE\s+'[^']*'/gi, "CURRENT_TIMESTAMP")
    .replace(/\bNOW\(\)/gi, "CURRENT_TIMESTAMP")
    .replace(/\bTRUE\b/g, "1")
    .replace(/\bFALSE\b/g, "0")
    .replace(/\bBTRIM\s*\(/gi, "TRIM(")
    .replace(/\bjsonb_typeof\s*\(/gi, "JSON_TYPE(")
    .replace(/\bjsonb_array_length\s*\(/gi, "JSON_ARRAY_LENGTH(")
    .replace(/\bNULLS\s+(FIRST|LAST)\b/gi, "")
    .replace(/\bSERIAL\s+PRIMARY\s+KEY\b/gi, "INTEGER PRIMARY KEY AUTOINCREMENT")
    .replace(/\bARRAY_AGG\s*\(\s*DISTINCT\s+([^)]+)\s*\)/gi, "json_group_array(DISTINCT $1)")
    .replace(/\bARRAY_AGG\s*\(\s*([^)]+)\s*\)/gi, "json_group_array($1)")
    .replace(/\bFOR\s+(UPDATE|SHARE)(\s+NOWAIT|\s+SKIP\s+LOCKED)?\b/gi, "")
    .replace(/\bgen_random_uuid\s*\(\s*\)/gi, "(lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' || substr(lower(hex(randomblob(3))),2) || '-' || printf('%x', (random() % 4 + 8)) || substr(lower(hex(randomblob(3))),2) || '-' || lower(hex(randomblob(6))))");

  // COUNT(*) FILTER (WHERE condition) -> SUM(CASE WHEN condition THEN 1 ELSE 0 END)
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
        if (ch === stringChar && sql[i - 1] !== "\\") inString = false;
        continue;
      }
      if (ch === "'" || ch === '"') {
        inString = true;
        stringChar = ch;
        continue;
      }
      if (ch === "(") depth++;
      else if (ch === ")" && --depth === 0) {
        endIdx = i;
        break;
      }
    }

    const condition = sql.slice(afterWhere, endIdx).trim();
    const replacement = `SUM(CASE WHEN ${condition} THEN 1 ELSE 0 END)`;
    sql = sql.slice(0, matchStart) + replacement + sql.slice(endIdx + 1);
    FILTER_RE.lastIndex = matchStart + replacement.length;
  }

  // to_char(expr, format)
  sql = sql.replace(/\bto_char\s*\(\s*([^,]+)\s*,\s*'([^']+)'\s*\)/gi, (_, expr, format) =>
    `strftime('${toCharFormatToStrftime(`'${format}'`)}', ${expr})`
  );

  // STRING_AGG
  sql = sql.replace(/\bSTRING_AGG\s*\(\s*DISTINCT\s+([^,]+)\s*,\s*('([^']*)'|"([^"]*)")\s*\)/gi, (_, expr, quotedSep, sepSingle, sepDouble) =>
    `replace(group_concat(DISTINCT ${expr}), ',', '${sepSingle !== undefined ? sepSingle : sepDouble}')`
  );
  sql = sql.replace(/\bSTRING_AGG\s*\(\s*([^,]+)\s*,\s*('([^']*)'|"([^"]*)")\s*\)/gi, (_, expr, quotedSep, sepSingle, sepDouble) =>
    `group_concat(${expr}, '${sepSingle !== undefined ? sepSingle : sepDouble}')`
  );

  // EXTRACT(field FROM expr)
  const extractMap = { HOUR: "%H", DAY: "%d", MONTH: "%m", YEAR: "%Y", EPOCH: "%s", MINUTE: "%M", SECOND: "%S" };
  sql = sql.replace(/\bEXTRACT\s*\(\s*(\w+)\s+FROM\s+([^)]+)\s*\)/gi, (match, field, expr) => {
    const fmt = extractMap[field.toUpperCase()];
    return fmt ? `CAST(strftime('${fmt}', ${expr}) AS INTEGER)` : match;
  });

  if (!/\$\d/.test(sql)) return { text: sql, values };

  // Positional parameters $N -> ? and = ANY($N) -> IN (?, ?, ...)
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
