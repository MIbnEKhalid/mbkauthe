# Dual-Database & Repository Architecture Guide

[Back to docs index](../README.md) | [Back to project README](../../README.md)

This guide documents the **standardized database and repository architecture** used across MBKTech applications, including how to implement **dual-database support (PostgreSQL + SQLite)** with `mbkauthe`'s unified database abstraction layer.

---

## 1. Standard Application Architecture

Every database-backed application adheres to the following unified directory structure:

```
src/
├── db/
│   ├── connection.js             # Pool / connection creation, configuration & test
│   ├── index.js                  # Instantiates & exports defaultAdapter (PostgresAdapter/SqliteAdapter), adapter, pool, dialects
│   └── schema/
│       ├── schema.sql            # PostgreSQL DDL
│       └── schema.sqlite.sql     # SQLite DDL (when supporting SQLite)
└── repositories/
    ├── <Domain>Repository.js     # Class extending BaseRepository from 'mbkauthe', constructor(adapter = defaultAdapter)
    └── index.js                  # Barrel export of repository classes & singletons
```

### Architectural Principles

1. **Separation of Concerns**:
   - `src/db/connection.js` owns low-level connection pooling, sizing, SSL, environment variables, and connection health-checks.
   - `src/db/index.js` layers the adapter/dialect abstraction (`PostgresAdapter` or `SqliteAdapter`) on top of the connection pool and exports driver-agnostic handles.
   - `src/repositories/` owns all SQL queries and business database operations. Routes and services never execute raw queries directly.
2. **Polymorphic Database Adapters**:
   - Repositories interact only with an `adapter` conforming to the unified query interface (`query(text, values)` and `connect()`), meaning repositories remain agnostic to whether the backend is PostgreSQL or SQLite.
3. **No Backward Compatibility Shims**:
   - Do not pass raw `pg.Pool` or SQLite handles directly into repository constructors. Always inject an adapter conforming to `BaseRepository`.
   - Never keep deprecated or legacy aliases (e.g., `src/config/db.js`, `database.js`).

---

## 2. Abstraction Primitives Provided by `mbkauthe`

Import these primitives directly from `"mbkauthe"`:

| Export | Description |
| :--- | :--- |
| `BaseRepository` | Extensible repository base class with `execute()`, `query()`, `withTransaction()`, `setDb()`, and dialect query-building helpers. |
| `PostgresAdapter` | PostgreSQL database adapter wrapping `pg.Pool`. Normalizes query execution, client acquisition, and binds `postgresDialect`. |
| `SqliteAdapter` | Unified SQLite database adapter/pool wrapping `better-sqlite3`. Manages connection, promise mutex, bind coercion, and row normalization. |
| `postgresDialect` | Dialect tokens for PostgreSQL (parameter placeholder `$1`, `NOW()`, `TRUE/FALSE`, quoting). |
| `sqliteDialect` | Dialect tokens for SQLite (parameter placeholder `?`, `CURRENT_TIMESTAMP`, `1/0`, quoting). |
| `translatePgToSqlite` | Translates PostgreSQL-flavored SQL to SQLite syntax at runtime. |
| `Mutex`, `SqliteClient` | Concurrency-safe FIFO promise mutex and transaction client handle for SQLite. |

---

## 3. Step-by-Step Implementation

### Step 1: Install Dependencies

In your application's `package.json`:
```json
{
  "dependencies": {
    "mbkauthe": "latest",
    "pg": "^8.16.3",
    "better-sqlite3": "^11.9.1"
  }
}
```

---

### Step 2: Database Connection (`src/db/connection.js`)

Create `src/db/connection.js` to manage the underlying pool or SQLite connection:

```javascript
// src/db/connection.js
import pkg from "pg";
const { Pool } = pkg;
import dotenv from "dotenv";

dotenv.config();

const dbType = (process.env.DB_TYPE || "postgres").toLowerCase();

export const poolConfig = {
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: true } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
};

export const pool = dbType !== "sqlite" ? new Pool(poolConfig) : null;

// Optional connection test on startup (skip during tests)
if (process.env.NODE_ENV !== "test" && pool) {
  (async () => {
    try {
      const client = await pool.connect();
      console.log("Connected to PostgreSQL database!");
      client.release();
    } catch (err) {
      console.error("Database connection error:", err.message);
    }
  })();
}

export default pool;
```

---

### Step 3: Database Index (`src/db/index.js`)

Create `src/db/index.js` to initialize the adapter layer:

```javascript
// src/db/index.js
import {
  PostgresAdapter,
  SqliteAdapter,
  postgresDialect,
  sqliteDialect,
  BaseRepository,
} from "mbkauthe";
import { pool, poolConfig } from "./connection.js";

const dbType = (process.env.DB_TYPE || "postgres").toLowerCase();

let defaultAdapter;

if (dbType === "sqlite") {
  const sqlitePath = process.env.SQLITE_PATH || "./data/app.db";
  defaultAdapter = new SqliteAdapter(sqlitePath, {
    dialect: sqliteDialect,
    jsonColumns: ["metadata", "settings"],
    booleanColumns: ["is_active", "is_published"],
  });
} else {
  defaultAdapter = new PostgresAdapter(pool, postgresDialect);
}

export const adapter = defaultAdapter;
export { defaultAdapter, pool, poolConfig };
export { PostgresAdapter, postgresDialect, SqliteAdapter, sqliteDialect, BaseRepository };
export default defaultAdapter;
```

---

### Step 4: Domain Repositories (`src/repositories/`)

Domain repositories extend `BaseRepository` and default to `defaultAdapter`:

```javascript
// src/repositories/UserRepository.js
import { BaseRepository } from "mbkauthe";
import { defaultAdapter } from "../db/index.js";

export class UserRepository extends BaseRepository {
  constructor(adapter = defaultAdapter) {
    super(adapter);
  }

  async findById(id) {
    const { rows } = await this.query(
      "SELECT id, username, email, is_active FROM users WHERE id = $1",
      [id]
    );
    return rows[0] || null;
  }

  async findActive({ limit = 20, offset = 0 } = {}) {
    const { rows } = await this.query(`
      SELECT id, username, email, created_at
      FROM users
      WHERE is_active = TRUE
      ORDER BY created_at DESC
      ${this.dialect.limitOffset({ limit, offset })}
    `);
    return rows || [];
  }

  async create(username, email, passwordHash) {
    const { rows } = await this.query(
      `INSERT INTO users (username, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username, email, created_at`,
      [username, email, passwordHash]
    );
    return rows[0];
  }
}

export const userRepository = new UserRepository();
export default userRepository;
```

Barrel-export all repository classes and singletons in `src/repositories/index.js`:

```javascript
// src/repositories/index.js
import { UserRepository, userRepository } from "./UserRepository.js";

export { UserRepository, userRepository };
export default userRepository;
```

---

### Step 5: Dynamic Re-targeting with `setDb()`

When switching databases dynamically (for example, in multi-tenant environments or during test setup), use `setDb()`:

```javascript
userRepository.setDb(newAdapter, newDialect);
```

This updates both `repo.db` and `repo.adapter`, and sets `repo.dialect` cleanly without reconstructing the repository instance.

---

### Step 6: Concurrency-Safe Transactions

Use `withTransaction` to execute multiple queries atomically:

```javascript
await orderRepository.withTransaction(async (txRepo, client) => {
  // Queries executed on txRepo run on the dedicated transaction connection
  await txRepo.query(
    "UPDATE accounts SET balance = balance - $1 WHERE id = $2",
    [amount, fromAccountId]
  );
  await txRepo.query(
    "UPDATE accounts SET balance = balance + $1 WHERE id = $2",
    [amount, toAccountId]
  );
  await txRepo.query(
    "INSERT INTO transfer_logs (from_id, to_id, amount) VALUES ($1, $2, $3)",
    [fromAccountId, toAccountId, amount]
  );
});
```

> [!WARNING]
> **Transaction Deadlock Rule in SQLite**:
> SQLite serializes write transactions with a FIFO Promise Mutex. Always execute queries inside `withTransaction` using the `txRepo` parameter. Querying the root `defaultAdapter` inside the callback will block waiting for the mutex lock and cause a deadlock.

---

## 4. SQL Syntax Translation Reference

When running in SQLite mode, `mbkauthe`'s built-in translation engine (`translatePgToSqlite`) transparently converts PostgreSQL SQL statements:

| PostgreSQL Syntax | Converted SQLite Syntax | Description |
| :--- | :--- | :--- |
| `$1, $2, $3` | `?, ?, ?` | Positional parameter re-indexing. |
| `col = ANY($1)` | `col IN (?, ?, ...)` | Automatically expands parameter arrays. |
| `::jsonb`, `::text`, `::int` | *(removed)* | Safe removal of Postgres typecasts. |
| `ILIKE` | `LIKE` | Case-insensitive matching. |
| `NOW()` / `CURRENT_TIMESTAMP` | `CURRENT_TIMESTAMP` | Maps current timestamp. |
| `TRUE` / `FALSE` | `1` / `0` | Coerces booleans to SQLite integers. |
| `BTRIM(col)` | `TRIM(col)` | Maps string trimming. |
| `jsonb_typeof(col)` | `JSON_TYPE(col)` | Uses SQLite JSON1 extension. |
| `COUNT(*) FILTER (WHERE ...)` | `SUM(CASE WHEN ... THEN 1 ELSE 0 END)` | Conditional aggregate translation. |
| `gen_random_uuid()` | Inline hex UUID v4 expression | Generates compliant RFC 4122 UUIDs. |

---

## 5. DDL Schema Management

Maintain clean, executable DDL schema definitions in `src/db/schema/`:

- **`src/db/schema/schema.sql`** (PostgreSQL DDL)
- **`src/db/schema/schema.sqlite.sql`** (SQLite DDL, if supporting SQLite)

### Data Type Mapping

| PostgreSQL Type | SQLite Column Type |
| :--- | :--- |
| `SERIAL PRIMARY KEY` | `INTEGER PRIMARY KEY AUTOINCREMENT` |
| `VARCHAR(n)`, `TEXT` | `TEXT` |
| `BOOLEAN` | `INTEGER` (`0` or `1`) |
| `JSONB`, `JSON` | `TEXT` (JSON-encoded string) |
| `TIMESTAMPTZ`, `TIMESTAMP` | `TEXT` (ISO 8601 string) |
| `BYTEA` | `BLOB` |

---

## 6. Zero-Dependency In-Memory Testing

In test environments (Vitest or Jest), configure SQLite `:memory:` for fast, isolated, serverless testing:

```javascript
// tests/setup.js
process.env.DB_TYPE = "sqlite";
process.env.SQLITE_PATH = ":memory:";

import { defaultAdapter } from "../src/db/index.js";
import { applySchema } from "mbkauthe";

export async function initTestDb() {
  await applySchema(defaultAdapter, "./src/db/schema/schema.sqlite.sql", { silent: true });
}
```

---

## 7. Unified Schema Runner (`applySchema`)

`applySchema` provides a centralized, idempotent schema execution helper that applies `.sql` files or raw SQL statements to either a `PostgresAdapter`, `pg.Pool`, or `SqliteAdapter`.

```javascript
import { applySchema } from "mbkauthe";
import path from "node:path";
import { pool } from "./connection.js";

export async function initDatabaseSchema() {
  const schemaPath = path.resolve("src/db/schema/schema.sql");
  await applySchema(pool, schemaPath, { name: "app-schema" });
}
```

### Supported Inputs and Options

- **Target**: `SqliteAdapter`, `better-sqlite3` instance, `PostgresAdapter`, or `pg.Pool`.
- **Source**: File path ending in `.sql` (or resolving to an existing file), or raw SQL string.
- **Options**:
  - `silent` (boolean, default: `false`): Suppress confirmation/error console logs.
  - `name` (string): Descriptive label displayed in log outputs.

---

## 8. Standardized Graceful Pool Shutdown

To prevent dropped queries and hanging process connections on termination, `mbkauthe` provides centralized signal handling and connection pool draining:

```javascript
// src/db/connection.js
import { registerGracefulShutdown, closeAllConnections } from "mbkauthe";
import { pool } from "./connection.js";

// Register pool for automatic SIGINT / SIGTERM draining
registerGracefulShutdown(pool);
```

### Key Features

1. **Automatic Signal Registration**: Hooks `process.once("SIGINT")` and `process.once("SIGTERM")` only once, draining all registered pools/adapters with `.end()` and `.close()`.
2. **Forced Timeout Safety**: Configurable timeout (default: `5000ms`) triggers a clean exit if a hanging connection refuses to terminate.
3. **Array and Map Registration**:
   ```javascript
   registerGracefulShutdown([mainPool, auditPool]);
   // or
   registerGracefulShutdown({ pool1, pool2, pool3 });
   ```
4. **Test Suite Teardown (`closeAllConnections`)**:
   In Jest or Vitest test teardowns, programmatically drain and unregister all connections without exiting the process:
   ```javascript
   import { closeAllConnections } from "mbkauthe";

   afterAll(async () => {
     await closeAllConnections();
   });
   ```

