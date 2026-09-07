import { vi } from "vitest";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { applySchema } from "../../lib/db/applySchema.js";
import { registerGracefulShutdown, closeAllConnections } from "../../lib/db/gracefulShutdown.js";
import { SqliteAdapter } from "../../lib/db/sqlitePool.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe("applySchema", () => {
  let sqlite;

  beforeEach(() => {
    sqlite = new SqliteAdapter(":memory:");
  });

  afterEach(async () => {
    if (sqlite) {
      await sqlite.end();
    }
  });

  it("applies raw SQL string to SqliteAdapter", async () => {
    const ddl = `
      CREATE TABLE test_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL
      );
    `;

    const result = await applySchema(sqlite, ddl, { silent: true });
    expect(result.success).toBe(true);

    await sqlite.query("INSERT INTO test_items (name) VALUES (?)", ["item1"]);
    const res = await sqlite.query("SELECT * FROM test_items");
    expect(res.rows).toHaveLength(1);
    expect(res.rows[0].name).toBe("item1");
  });

  it("applies schema from a .sql file", async () => {
    const tempSqlFile = path.join(__dirname, "temp_test_schema.sql");
    fs.writeFileSync(
      tempSqlFile,
      `CREATE TABLE test_from_file (id INTEGER PRIMARY KEY, title TEXT);`
    );

    try {
      const result = await applySchema(sqlite, tempSqlFile, { silent: true });
      expect(result.success).toBe(true);

      const res = await sqlite.query("SELECT name FROM sqlite_master WHERE type='table' AND name='test_from_file'");
      expect(res.rows).toHaveLength(1);
    } finally {
      if (fs.existsSync(tempSqlFile)) {
        fs.unlinkSync(tempSqlFile);
      }
    }
  });

  it("handles empty or whitespace SQL gracefully", async () => {
    const result = await applySchema(sqlite, "   \n  \t  ", { silent: true });
    expect(result.success).toBe(true);
  });

  it("applies schema to a mock PostgresAdapter or pg.Pool via query()", async () => {
    const mockQueries = [];
    const mockPostgres = {
      query: vi.fn(async (sql) => {
        mockQueries.push(sql);
        return { rows: [], rowCount: 0 };
      }),
    };

    const ddl = "CREATE TABLE pg_test (id SERIAL PRIMARY KEY);";
    const result = await applySchema(mockPostgres, ddl, { silent: true, name: "pg-mock" });

    expect(result.success).toBe(true);
    expect(mockPostgres.query).toHaveBeenCalledWith(ddl);
  });

  it("throws error for invalid adapter without exec or query", async () => {
    await expect(applySchema({}, "CREATE TABLE x (id INT);", { silent: true }))
      .rejects.toThrow("Invalid adapterOrPool");
  });

  it("propagates SQL execution errors", async () => {
    await expect(applySchema(sqlite, "INVALID SQL SYNTAX HERE !!!", { silent: true }))
      .rejects.toThrow();
  });
});

describe("registerGracefulShutdown & closeAllConnections", () => {
  afterEach(async () => {
    await closeAllConnections();
  });

  it("registers single target with end() and closes it", async () => {
    const mockPool = { end: vi.fn().mockResolvedValue(true) };
    registerGracefulShutdown(mockPool);

    await closeAllConnections();
    expect(mockPool.end).toHaveBeenCalledTimes(1);
  });

  it("registers single target with close() and closes it", async () => {
    const mockAdapter = { close: vi.fn() };
    registerGracefulShutdown(mockAdapter);

    await closeAllConnections();
    expect(mockAdapter.close).toHaveBeenCalledTimes(1);
  });

  it("registers an array of targets", async () => {
    const target1 = { end: vi.fn().mockResolvedValue(true) };
    const target2 = { close: vi.fn() };

    registerGracefulShutdown([target1, target2]);
    await closeAllConnections();

    expect(target1.end).toHaveBeenCalledTimes(1);
    expect(target2.close).toHaveBeenCalledTimes(1);
  });

  it("registers an object map of targets", async () => {
    const poolA = { end: vi.fn().mockResolvedValue(true) };
    const poolB = { close: vi.fn() };

    registerGracefulShutdown({ poolA, poolB });
    await closeAllConnections();

    expect(poolA.end).toHaveBeenCalledTimes(1);
    expect(poolB.close).toHaveBeenCalledTimes(1);
  });

  it("is idempotent: subsequent closeAllConnections does nothing", async () => {
    const mockPool = { end: vi.fn().mockResolvedValue(true) };
    registerGracefulShutdown(mockPool);

    await closeAllConnections();
    expect(mockPool.end).toHaveBeenCalledTimes(1);

    await closeAllConnections();
    expect(mockPool.end).toHaveBeenCalledTimes(1);
  });

  it("handles errors gracefully during shutdown without throwing", async () => {
    const badTarget = {
      end: vi.fn().mockRejectedValue(new Error("Connection closing error")),
    };
    const goodTarget = {
      close: vi.fn(),
    };

    registerGracefulShutdown([badTarget, goodTarget]);
    await expect(closeAllConnections()).resolves.not.toThrow();

    expect(badTarget.end).toHaveBeenCalledTimes(1);
    expect(goodTarget.close).toHaveBeenCalledTimes(1);
  });
});
