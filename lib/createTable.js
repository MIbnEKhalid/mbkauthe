import { dblogin, dbType } from "./pool.js";
import { readFile } from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { performance } from "perf_hooks";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
  const startTime = performance.now();
  console.log(`[mbkauthe] Starting schema creation (Database type: ${dbType})...`);

  const schemaFile = dbType === "sqlite" ? "db.sqlite.sql" : "db.sql";
  const schemaPath = path.resolve(__dirname, "../docs/schema", schemaFile);
  const schemaSql = await readFile(schemaPath, "utf8");

  const statementCount = schemaSql.split(";").map((s) => s.trim()).filter(Boolean).length;
  console.log(`[mbkauthe] Schema loaded (${Buffer.byteLength(schemaSql, "utf8")} bytes, ~${statementCount} statements)`);

  try {
    const queryStart = performance.now();
    if (dbType === "sqlite") {
      dblogin.execScript(schemaSql);
    } else {
      const ping = await dblogin.query("SELECT version()");
      console.log(`[mbkauthe] Connected to PostgreSQL (${ping.rows[0].version})`);
      const res = await dblogin.query(schemaSql);
      console.log(`[mbkauthe] Command: ${res.command ?? "MULTI"}, Row count: ${res.rowCount ?? 0}`);
    }
    const queryDuration = (performance.now() - queryStart).toFixed(2);
    console.log(`[mbkauthe] Schema applied successfully in ${queryDuration} ms`);
  } catch (err) {
    const IGNORE_CODES = ["42710", "42P07"];
    if (err && typeof err.code === "string" && IGNORE_CODES.includes(err.code)) {
      console.warn(`[mbkauthe] Schema object already exists (ignored): ${err.code} - ${err.message}`);
    } else {
      console.error("[mbkauthe] Failed to apply schema:", err.message || err);
      process.exitCode = 1;
    }
  } finally {
    console.log("[mbkauthe] Closing database connection...");
    await dblogin.end();
    console.log(`[mbkauthe] Finished in ${(performance.now() - startTime).toFixed(2)} ms`);
  }
}

main();
