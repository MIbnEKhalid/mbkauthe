/**
 * Best-effort translator for the subset of Postgres SQL used in mbkauthe queries.
 */
export function translatePgToSqlite(text, values = []) {
  const sql = String(text ?? "")
    .replace(/::\w+(\[\])?/g, "")
    .replace(/\bNOW\(\)/gi, "CURRENT_TIMESTAMP")
    .replace(/\bTRUE\b/g, "1")
    .replace(/\bFALSE\b/g, "0");

  if (!/\$\d/.test(sql)) return { text: sql, values };

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
