# Dual-Database Engine in MBKAuthe v6

MBKAuthe v6 provides first-class dual-database persistence. You can switch between **PostgreSQL** (production connection-pooled database) and **SQLite** (zero-config embedded database via `better-sqlite3`) by simply setting `DB_TYPE=postgres` or `DB_TYPE=sqlite`.

---

## 1. Database Adapters

MBKAuthe uses the `IDatabaseAdapter` abstraction to provide consistent async query interfaces:

```typescript
export interface IDatabaseAdapter {
  query(sql: string, params?: any[]): Promise<QueryResult>;
  close(): Promise<void>;
  isAlive(): Promise<boolean>;
}
```

### PostgreSQL (`PostgresAdapter`)
- Built on Node `pg` (`pg.Pool`).
- Configured with automatic connection pooling and SSL support.
- Uses parameterized positional placeholders (`$1, $2, ...`).

### SQLite (`SqliteAdapter`)
- Built on `better-sqlite3`.
- Automatically activates **WAL mode** (`PRAGMA journal_mode = WAL;`) for high concurrency and fast reads.
- Synchronized through `SqliteMutex` (FIFO promise queue) to eliminate `SQLITE_BUSY` database lock conflicts under heavy write traffic.
- Uses positional placeholders (`?, ?, ...`).

---

## 2. Setting Up PostgreSQL

Set `DB_TYPE=postgres` and provide your connection URL:

```env
DB_TYPE=postgres
LOGIN_DB=postgres://postgres:password@localhost:5432/mbkauthe_db
```

### Running Table Creation

To apply the schema tables, foreign keys, and indexes:

```typescript
import { applySchema, dblogin, dialect } from "mbkauthe/db";

async function setup() {
  await applySchema(dblogin, "postgres");
  console.log("PostgreSQL tables and indexes created successfully.");
}

setup();
```

---

## 3. Setting Up SQLite

Set `DB_TYPE=sqlite` and specify the SQLite file path:

```env
DB_TYPE=sqlite
SQLITE_PATH=./data/mbkauthe.sqlite
```

The directory and database file are created automatically if they do not exist.

### Applying SQLite Schema

```typescript
import { applySchema, dblogin, dialect } from "mbkauthe/db";

async function setup() {
  await applySchema(dblogin, "sqlite");
  console.log("SQLite schema created successfully.");
}

setup();
```

---

## 4. Automatic Retries & Resilience (`dbRetry`)

MBKAuthe automatically wraps query execution with exponential backoff and jitter for transient database failures:

- **Connection Dropouts & Timeouts**: Retries up to 3 times before throwing.
- **Deadlocks / Serialization Failures**: PostgreSQL error codes `40P01` / `40001`.
- **SQLite Locks**: Automatic retry with progressive delay.

```typescript
import { withQueryRetry } from "mbkauthe/db";

const result = await withQueryRetry(
  () => dblogin.query("SELECT * FROM mbkcore_users WHERE username = $1", ["alice"]),
  { maxAttempts: 3, baseDelayMs: 150, maxDelayMs: 2000 }
);
```

---

## 5. Live Query Logging & Diagnostics

For debugging and performance profiling in development mode, MBKAuthe includes an in-memory query logger (enabled when `DB_LOGS=true` or `process.env.dbLogs="true"`):

```typescript
import { getQueryLog, getQueryCount, resetQueryLog } from "mbkauthe/db";

// Retrieve recent queries with execution time
const logs = getQueryLog();
console.log(`Executed ${getQueryCount()} queries:`, logs);

// Reset log buffer
resetQueryLog();
```
