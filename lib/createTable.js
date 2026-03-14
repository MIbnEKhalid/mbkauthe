import { dblogin } from "./pool.js";
import { readFile } from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
  const schemaPath = path.resolve(__dirname, "../docs/db.sql");
  const schemaSql = await readFile(schemaPath, "utf8");

  try {
    const res = await dblogin.query(schemaSql);
    console.log("[mbkauthe] Schema applied successfully.");
    if (res?.rows?.length) {
      console.log(res.rows);
    } else {
      console.log("[mbkauthe] No rows returned by schema query (expected). If you want to verify table creation, query the database separately.");
    }
  } catch (err) {
    const IGNORE_CODES = ["42710", "42P07"];
    if (err && typeof err.code === "string" && IGNORE_CODES.includes(err.code)) {
      console.warn("[mbkauthe] Schema already exists (ignored):", err.message);
    } else {
      console.error("[mbkauthe] Failed to apply schema:", err);
      process.exitCode = 1;
    }
  } finally {
    await dblogin.end();
  }
}

main();
