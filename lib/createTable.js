import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import { dblogin, dbType } from "./pool.js";
import { applySchema } from "./db/applySchema.js";

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
    await applySchema(dblogin, schemaPath, { name: schemaFile });
    console.log(`[mbkauthe] Schema applied successfully in ${(performance.now() - queryStart).toFixed(2)} ms`);
  } catch (err) {
    if (["42710", "42P07"].includes(err?.code)) {
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
