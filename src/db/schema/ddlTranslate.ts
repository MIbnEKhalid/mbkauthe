function toCharFormatToStrftime(pgFormat: string): string {
  const literals: string[] = [];
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

const TRANSLATION_CACHE_MAX = 1000;
const translationCache = new Map<string, string>();

function translateSqlTemplate(text: string): string {
  if (translationCache.has(text)) {
    return translationCache.get(text)!;
  }

  let sql = String(text ?? "");

  // 1. Mask SQL comments so keywords inside comments are not modified
  const comments: string[] = [];
  sql = sql.replace(/\/\*[\s\S]*?\*\/|--.*$/gm, (m) => {
    comments.push(m);
    return `\x00CMT_${comments.length - 1}\x00`;
  });

  // 2. Mask single-quoted string literals so regex transforms don't mutate user string contents
  const literals: string[] = [];
  sql = sql.replace(/'(?:''|[^'])*'/g, (m) => {
    literals.push(m);
    return `\x00LIT_${literals.length - 1}\x00`;
  });

  // 3. Date & Interval arithmetic:
  // e.g. NOW() - INTERVAL '7 days' or CURRENT_TIMESTAMP + INTERVAL '1 day'
  sql = sql.replace(
    /\b(?:NOW\(\)|CURRENT_TIMESTAMP)\s*([+-])\s*INTERVAL\s*(\x00LIT_\d+\x00|'[^']+')/gi,
    (_, op, rawLit) => {
      let intervalStr = rawLit;
      if (rawLit.startsWith("\x00LIT_")) {
        const idx = Number(rawLit.slice(5, -1));
        intervalStr = literals[idx] || "''";
      }
      const cleaned = intervalStr.replace(/^'|'$/g, "").trim();
      return `DATETIME('now', '${op === "-" ? "-" : "+"}${cleaned}')`;
    }
  );

  // General INTERVAL on expressions/columns: expr + INTERVAL 'N days' -> DATETIME(expr, '+N days')
  sql = sql.replace(
    /([a-zA-Z0-9_\.]+)\s*([+-])\s*INTERVAL\s*(\x00LIT_\d+\x00|'[^']+')/gi,
    (_, col, op, rawLit) => {
      let intervalStr = rawLit;
      if (rawLit.startsWith("\x00LIT_")) {
        const idx = Number(rawLit.slice(5, -1));
        intervalStr = literals[idx] || "''";
      }
      const cleaned = intervalStr.replace(/^'|'$/g, "").trim();
      return `DATETIME(${col}, '${op === "-" ? "-" : "+"}${cleaned}')`;
    }
  );

  sql = sql
    .replace(/::\w+(?:\s*\([^)]*\))?(?:\s*\[\])?/g, "")
    .replace(/\bILIKE\b/gi, "LIKE")
    .replace(/\bNOW\(\)\s+AT\s+TIME\s+ZONE\s+(\x00LIT_\d+\x00|'[^']*')/gi, "CURRENT_TIMESTAMP")
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

  // GREATEST(...) and LEAST(...) -> MAX(...) and MIN(...)
  sql = sql
    .replace(/\bGREATEST\s*\(/gi, "MAX(")
    .replace(/\bLEAST\s*\(/gi, "MIN(");

  // POSITION(needle IN haystack) / STRPOS(haystack, needle) -> INSTR(haystack, needle)
  sql = sql
    .replace(/\bPOSITION\s*\(\s*([^)]+?)\s+IN\s+([^)]+?)\s*\)/gi, "INSTR($2, $1)")
    .replace(/\bSTRPOS\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)/gi, "INSTR($1, $2)");

  // SUBSTRING(str FROM start FOR len) -> SUBSTR(str, start, len)
  sql = sql
    .replace(/\bSUBSTRING\s*\(\s*([^,]+?)\s+FROM\s+([^,]+?)\s+FOR\s+([^)]+?)\s*\)/gi, "SUBSTR($1, $2, $3)")
    .replace(/\bSUBSTRING\s*\(\s*([^,]+?)\s+FROM\s+([^)]+?)\s*\)/gi, "SUBSTR($1, $2)");

  // COUNT(*) FILTER (WHERE condition) -> SUM(CASE WHEN condition THEN 1 ELSE 0 END)
  const FILTER_RE = /COUNT\s*\(\s*\*\s*\)\s+FILTER\s*\(WHERE\s+/gi;
  let filterMatch;
  while ((filterMatch = FILTER_RE.exec(sql)) !== null) {
    const matchStart = filterMatch.index;
    const afterWhere = matchStart + filterMatch[0].length;
    let depth = 1;
    let endIdx = afterWhere;
    let inString = false;
    let stringChar: string | null = null;

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
  sql = sql.replace(/\bto_char\s*\(\s*([^,]+)\s*,\s*(\x00LIT_\d+\x00|'[^']+')\s*\)/gi, (_, expr, rawLit) => {
    let fmtStr = rawLit;
    if (rawLit.startsWith("\x00LIT_")) {
      const idx = Number(rawLit.slice(5, -1));
      fmtStr = literals[idx] || "''";
    }
    return `strftime('${toCharFormatToStrftime(fmtStr)}', ${expr})`;
  });

  // STRING_AGG
  sql = sql.replace(/\bSTRING_AGG\s*\(\s*DISTINCT\s+([^,]+)\s*,\s*(\x00LIT_\d+\x00|'([^']*)'|"([^"]*)")\s*\)/gi, (_, expr, fullLit, sepSingle, sepDouble) => {
    let sep = fullLit;
    if (fullLit.startsWith("\x00LIT_")) {
      const idx = Number(fullLit.slice(5, -1));
      sep = literals[idx] || "','";
    } else {
      sep = sepSingle !== undefined ? `'${sepSingle}'` : `'${sepDouble}'`;
    }
    return `replace(group_concat(DISTINCT ${expr}), ',', ${sep})`;
  });
  sql = sql.replace(/\bSTRING_AGG\s*\(\s*([^,]+)\s*,\s*(\x00LIT_\d+\x00|'([^']*)'|"([^"]*)")\s*\)/gi, (_, expr, fullLit, sepSingle, sepDouble) => {
    let sep = fullLit;
    if (fullLit.startsWith("\x00LIT_")) {
      const idx = Number(fullLit.slice(5, -1));
      sep = literals[idx] || "','";
    } else {
      sep = sepSingle !== undefined ? `'${sepSingle}'` : `'${sepDouble}'`;
    }
    return `group_concat(${expr}, ${sep})`;
  });

  // EXTRACT(field FROM expr)
  const extractMap: Record<string, string> = { HOUR: "%H", DAY: "%d", MONTH: "%m", YEAR: "%Y", EPOCH: "%s", MINUTE: "%M", SECOND: "%S" };
  sql = sql.replace(/\bEXTRACT\s*\(\s*(\w+)\s+FROM\s+([^)]+)\s*\)/gi, (match, field, expr) => {
    const fmt = extractMap[field.toUpperCase()];
    return fmt ? `CAST(strftime('${fmt}', ${expr}) AS INTEGER)` : match;
  });

  // 4. Restore single-quoted literals and comments
  sql = sql.replace(/\x00LIT_(\d+)\x00/g, (_, idx) => literals[Number(idx)]);
  sql = sql.replace(/\x00CMT_(\d+)\x00/g, (_, idx) => comments[Number(idx)]);

  if (translationCache.size >= TRANSLATION_CACHE_MAX) {
    const firstKey = translationCache.keys().next().value;
    if (firstKey) translationCache.delete(firstKey);
  }
  translationCache.set(text, sql);
  return sql;
}

export function translatePgToSqlite(text: string, values: any[] = []): { text: string; values: any[] } {
  const sql = translateSqlTemplate(text);

  if (!/\$\d/.test(sql)) return { text: sql, values };

  // Positional parameters $N -> ? and = ANY($N) -> IN (?, ?, ...)
  const tokenRegex = /(=\s*ANY\(\$(\d+)\))|(\$(\d+))/g;
  let out = "";
  let lastIndex = 0;
  let match;
  const newValues: any[] = [];

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
