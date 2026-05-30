import { dblogin } from "./pool.js";
import { readFile } from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { performance } from "perf_hooks";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
  const startTime = performance.now();

  console.log("[mbkauthe] Starting schema creation...");

  const schemaPath = path.resolve(__dirname, "../docs/db.sql");

  console.log(`[mbkauthe] Schema file: ${schemaPath}`);

  const schemaSql = await readFile(schemaPath, "utf8");

  console.log(
    `[mbkauthe] Schema loaded (${Buffer.byteLength(schemaSql, "utf8")} bytes)`
  );

  const statementCount = schemaSql
    .split(";")
    .map(s => s.trim())
    .filter(Boolean).length;

  console.log(
    `[mbkauthe] Detected approximately ${statementCount} SQL statements`
  );

  try {
    console.log("[mbkauthe] Testing database connection...");

    const ping = await dblogin.query("SELECT version()");

    console.log(
      `[mbkauthe] Connected to PostgreSQL`
    );

    console.log(
      `[mbkauthe] PostgreSQL version: ${ping.rows[0].version}`
    );

    console.log("[mbkauthe] Applying schema...");

    const queryStart = performance.now();

    const res = await dblogin.query(schemaSql);

    const queryDuration = (
      performance.now() - queryStart
    ).toFixed(2);

    console.log(
      `[mbkauthe] Schema applied successfully in ${queryDuration} ms`
    );

    console.log(
      `[mbkauthe] Command: ${res.command ?? "MULTI"}`
    );

    console.log(
      `[mbkauthe] Row count: ${res.rowCount ?? 0}`
    );

    if (res?.rows?.length) {
      console.log(
        `[mbkauthe] Returned rows: ${res.rows.length}`
      );
    }

  } catch (err) {
    const IGNORE_CODES = ["42710", "42P07"];

    if (
      err &&
      typeof err.code === "string" &&
      IGNORE_CODES.includes(err.code)
    ) {
      console.warn(
        `[mbkauthe] Schema object already exists (ignored)`
      );

      console.warn(`Code: ${err.code}`);
      console.warn(`Message: ${err.message}`);
    } else {
      console.error(
        `[mbkauthe] Failed to apply schema`
      );

      console.error("Code:", err.code);
      console.error("Severity:", err.severity);
      console.error("Position:", err.position);
      console.error("Table:", err.table);
      console.error("Column:", err.column);
      console.error("Constraint:", err.constraint);
      console.error("Detail:", err.detail);
      console.error("Hint:", err.hint);
      console.error("Message:", err.message);

      process.exitCode = 1;
    }
  } finally {
    console.log("[mbkauthe] Closing database connection...");

    await dblogin.end();

    const totalDuration = (
      performance.now() - startTime
    ).toFixed(2);

    console.log(
      `[mbkauthe] Finished in ${totalDuration} ms`
    );
  }
}

main();