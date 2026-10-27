# Database Architecture & Repositories Guide

MBKAuthe v6 features a layered data access architecture based on the **Repository Pattern** and dynamic **SQL Dialect Translation**. This ensures consistent behavior, high performance, and complete portability across PostgreSQL and SQLite.

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────┐
│                   Domain Repositories                  │
│  UserRepository │ SessionRepository │ AuthRepository   │
│  PermissionRepository │ ApiTokenRepository │ ...       │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│                     BaseRepository                     │
│  findById │ findOne │ findMany │ insert │ update │ del │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│                    Dialect Engine                      │
│   postgresDialect ($1, RETURNING) │ sqliteDialect (?)  │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│                   Connection Pools                     │
│   PostgresAdapter (pg.Pool) │ SqliteAdapter (+Mutex)   │
└────────────────────────────────────────────────────────┘
```

---

## 1. The `BaseRepository` Class

All domain repositories extend `BaseRepository<T>`, providing typed CRUD operations that automatically adapt to the active SQL dialect:

```typescript
import { BaseRepository, dblogin, dialect } from "mbkauthe/db";

export interface Organization {
  id: number;
  name: string;
  created_at: Date;
}

export class OrganizationRepository extends BaseRepository<Organization> {
  constructor() {
    super("organizations", dblogin, dialect);
  }

  async findByName(name: string): Promise<Organization | null> {
    return this.findOne({ name });
  }

  async createOrganization(name: string): Promise<Organization> {
    return this.insert({ name });
  }
}

export const organizationRepository = new OrganizationRepository();
```

---

## 2. SQL Dialect Translation & Execution Engine

MBKAuthe normalizes SQL syntax differences across database engines while preserving maximum execution performance:

| Feature | PostgreSQL (`PostgresDialect`) | SQLite (`SqliteDialect`) |
|---|---|---|
| Placeholders | `$1, $2, $3, ...` | `?, ?, ?, ...` (mapped automatically) |
| Array Unfolding | `= ANY($1)` | `IN (?, ?, ...)` (dynamically unnested) |
| Insert ID Return | `RETURNING id, ...` | `RETURNING id, ...` or `last_insert_rowid()` |
| Date Functions | `NOW()`, `NOW() - INTERVAL '7 days'` | `CURRENT_TIMESTAMP`, `DATETIME('now', '-7 days')` |
| Boolean Types | Native `BOOLEAN` (`true`/`false`) | `INTEGER` (`1`/`0`) |
| Case Sensitivity | `ILIKE` | `LIKE` |
| Aggregations | `STRING_AGG(col, ', ')` | `group_concat(col, ', ')` |
| Array Aggregations | `ARRAY_AGG(col)` | `json_group_array(col)` |
| Filter Aggregates | `COUNT(*) FILTER (WHERE ...)` | `SUM(CASE WHEN ... THEN 1 ELSE 0 END)` |
| Extremes | `GREATEST(a, b)`, `LEAST(a, b)` | `MAX(a, b)`, `MIN(a, b)` |
| String Extraction | `SUBSTRING(s FROM 1 FOR 4)` | `SUBSTR(s, 1, 4)` |
| String Position | `POSITION('x' IN s)`, `STRPOS(s, 'x')` | `INSTR(s, 'x')` |
| UUID Generation | `gen_random_uuid()` | RFC 4122 v4 Hex Blob Expression |

### Core Engine Optimizations

#### A. Prepared Statement Caching (LRU)
`SqliteAdapter` caches precompiled `better-sqlite3` statements in an LRU cache (`_stmtCache` up to 500 statements). Repetitive queries bypass VDBE bytecode compilation, improving SQLite throughput by **3x to 5x**.

#### B. Asynchronous Reader-Writer Lock (RWLock)
`SqliteAdapter` uses an asynchronous RWLock (`SqliteMutex`):
- **Read-Only Queries** (`SELECT`, `PRAGMA`, `EXPLAIN`): Acquire shared read locks (`acquireRead()`) allowing concurrent readers to execute in parallel in WAL mode without blocking each other.
- **Mutating Queries** (`INSERT`, `UPDATE`, `DELETE`, `BEGIN`): Acquire exclusive write locks (`acquireWrite()`) to serialize writes and eliminate `SQLITE_BUSY` database lock conflicts.

#### C. String Literal & Comment Masking
The translation engine safely masks single-quoted string literals (`'...'`) and comments (`/* ... */`, `-- ...`) prior to running syntax transformations. This ensures that user data containing keywords (e.g. `'Status is TRUE'`, `'admin::root'`) are never mutated or corrupted.

#### D. Adaptive Heuristic Row Normalization
Columns ending in `_at`, `_date`, or `_time` are automatically parsed into native JavaScript `Date` instances, while columns ending in `_meta`, `_json`, or matching JSON arrays/objects are parsed from JSON strings automatically without requiring manual schema column registration.

#### E. Production SQLite PRAGMAs
Connections automatically initialize with optimal engine tuning:
- `journal_mode = WAL` (Write-Ahead Logging for high concurrency)
- `synchronous = NORMAL` & `busy_timeout = 5000`
- `cache_size = -64000` (64MB memory page cache)
- `temp_store = MEMORY` (In-memory temporary tables and indexes)
- `mmap_size = 268435456` (256MB memory-mapped I/O)

---

## 3. Built-in Repositories

MBKAuthe exposes pre-instantiated singleton repositories for all domain models:

- `userRepository`: User records, passwords, roles, status, and OAuth linking.
- `sessionRepository`: Active sessions, device identifiers, expiry, and pruning.
- `authRepository`: Centralized authentication queries and login updates.
- `permissionRepository`: Dynamic permission catalog and role registry persistence.
- `apiTokenRepository`: Personal access tokens, hashes, and scopes.
- `cliAuthSessionRepository`: RFC 8628 device authorization requests and polling.
- `passkeyRepository`: WebAuthn / FIDO2 public keys, credential IDs, and counter management.

### Example: Using `UserRepository` & `SessionRepository`

```typescript
import { userRepository, sessionRepository } from "mbkauthe/repositories";

// Find user by username
const user = await userRepository.findByUsername("john_doe");
if (user) {
  console.log(`User ID: ${user.id}, Role: ${user.role}`);
}

// Prune oldest sessions or fetch active session
await sessionRepository.deleteOldestSessionsForUser(user.username, 2);
```

---

## 4. Graceful Shutdown & Connection Cleanup

MBKAuthe provides clean connection pool teardown helpers for process termination:

```typescript
import { registerGracefulShutdown, closeAllConnections } from "mbkauthe/db";

// Automatically registers SIGINT, SIGTERM, and beforeExit hooks
registerGracefulShutdown();

// Or invoke programmatically during custom server shutdown:
await closeAllConnections();
```
