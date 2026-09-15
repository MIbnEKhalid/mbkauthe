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

## 2. SQL Dialect Translation (`IDialect`)

MBKAuthe normalizes SQL syntax differences across database engines:

| Feature | PostgreSQL (`PostgresDialect`) | SQLite (`SqliteDialect`) |
|---|---|---|
| Placeholders | `$1, $2, $3, ...` | `?, ?, ?, ...` |
| Insert ID Return | `RETURNING id` | `SELECT last_insert_rowid() AS id` |
| Date Functions | `NOW()`, `NOW() - INTERVAL '7 days'` | `DATETIME('now')`, `DATETIME('now', '-7 days')` |
| Boolean Types | Native `BOOLEAN` (`true`/`false`) | `INTEGER` (`1`/`0`) |
| Case Sensitivity | `ILIKE` or `LOWER(col) = LOWER(val)` | `LOWER(col) = LOWER(val)` |

### Dynamic DDL Translation (`translatePgToSqlite`)

MBKAuthe includes a DDL translation utility that converts standard PostgreSQL `CREATE TABLE` definitions into SQLite-compatible schemas automatically.

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

// Prune expired sessions for a user
await sessionRepository.pruneUserSessions(user.id, 5);
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
