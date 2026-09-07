# Database Schema

[Back to docs index](../README.md) | [Back to project README](../../README.md)

**Executable DDL lives only in [`docs/schema/db.sql`](../schema/db.sql) (Postgres) and [`docs/schema/db.sqlite.sql`](../schema/db.sqlite.sql) (SQLite).** This file explains what those scripts create and how the app uses them. Run the Postgres script when bootstrapping or aligning a database (for example `psql $DATABASE_URL -f docs/schema/db.sql`). The app can also apply the right script for the configured backend via `lib/createTable.js`.

---

## 1. Roles

Postgres enum `role`: `superadmin`, `normaluser`, `guest`, `member`. The script creates the type only if it does not already exist. `users.role` defaults to `normaluser`.

---

## 2. Users

Core accounts table (`users`): username, activation flag, role, mail flag, `allowed_apps` and `positions` as JSONB, timestamps, optional `last_login`, and password hash column `password_enc` (no plaintext passwords).

Profile-style columns include `full_name`, `user_id` (exactly 9 characters, unique business identifier assigned externally), `email`, `image`, `bio`, `social_accounts`, and password-reset fields (`reset_token`, `reset_token_expires`, `reset_attempts`, `last_reset_attempt`).

Indexes cover username, role, active, email, last login, and GIN indexes on JSONB for `allowed_apps` and `positions`. The SQL file also adds optional covering indexes used on hot auth paths.

---

## 3. OAuth: `user_github` and `user_google`

Link rows from `users(username)` to GitHub or Google identities (provider ids, usernames/emails, tokens, timestamps). `user_github` may be altered by the script to add `installation_id` and `installation_target_type` if missing (idempotent migrations).

---

## 4. Sessions

- **`sessions`** — App session rows: UUID `id`, `username`, `created_at`, optional `expires_at`, optional `meta` JSONB. Requires `gen_random_uuid()` (e.g. `pgcrypto`). Extra indexes support expiry cleanup and middleware lookups.
- **`session`** — `express-session` Postgres store: `sid`, `sess` JSONB, `expire`, plus `username` and `last_activity` as in `db.sql`.

---

## 5. Two-factor: `TwoFA`

Per-user 2FA flag and secret, keyed by `username`.

---

## 6. Trusted devices: `trusted_devices`

Remembered devices (token, optional name, user agent, IP, created/expires/last-used) to skip repeated 2FA when valid.

---

## 7. API tokens: `api_tokens`

Named tokens per user: hash and prefix for lookup, optional expiry, `last_used`, and `permissions` JSONB with constraints defined in SQL.

### Related tables for token issuance

- **`api_token_profiles`** — predefined API-token templates consumed by the browser-based CLI/device login flow. MBKAuthe reads the active profile to build a token from its scope, app restrictions, and expiration policy.
- **`cli_auth_sessions`** — one-time browser/device login sessions. Each row stores hashed user/device codes, a pending raw token (until delivery), status (`pending`, `approved`, `completed`, `denied`, `expired`), and the profile id used to issue the token.

### `Permissions` shape (JSONB)

```json
{
  "scope": "read-only" | "write",
  "allowed_apps": null | ["app1", "app2"] | ["*"] | []
}
```

- **`scope`:** `read-only` limits to safe methods (GET, HEAD, OPTIONS); `write` allows mutating methods.
- **`allowed_apps`:** `null` inherits the user’s `allowed_apps` from `users`; a string array restricts to those apps (subset of the user’s apps); `["*"]` means all of the user’s apps (superadmin: system-wide); `[]` effectively disables app access.

superadmin users bypass app checks in the app layer; token `allowed_apps` still matters for non–superadmin users.

---

## 8. Seed data

`db.sql` inserts a default `support` user with a precomputed hash (documented there). Change that password immediately in production.

---

## 9. Other tables in `db.sql`

- **`todos`** — Tasks keyed by `username` → `users`, with type (`personal` / `admin`), completion, assignment fields, and several btree indexes for listing/filtering.
- **`plan_upgrade_requests`** — Role/plan upgrade workflow: requester, requested role/plan, reason, optional links, status (`pending` / `approved` / `rejected`), admin review fields, timestamps, and indexes for admin queues.

---

## Adding users without duplicating SQL

Use `hashPassword(password, username)` from the library so `password_enc` matches login verification (username participates as salt input).

```javascript
import { hashPassword } from "mbkauthe";
const encryptedPassword = hashPassword("your-password", "newusername");
// INSERT ... password_enc = encryptedPassword (see column list in db.sql)
```

Replace usernames, roles (`superadmin`, `normaluser`, `guest`, `member`), and flags (`active`, `have_mail_account`) to match your needs.

---

## SQLite backend notes

When `DB_TYPE` is `sqlite` (see the [configuration guide](configuration.md)), the app uses one `better-sqlite3` connection wrapped by `lib/db/sqlitePool.js`. The schema comes from [`docs/schema/db.sqlite.sql`](../schema/db.sqlite.sql) instead of `db.sql`.

- The database runs in WAL journal mode with foreign keys enabled. Expect `-wal` and `-shm` side files next to the database file; do not delete them while the app is running, and include them when copying a live database (or checkpoint first with `PRAGMA wal_checkpoint(TRUNCATE)`).
- Concurrent requests are safe: an internal FIFO mutex serializes statements so a plain query can never run inside another request's open transaction.

### Warning: inside a transaction, only use `txRepo`

The mutex is not re-entrant. `pool.query()` waits for the mutex, and an open transaction holds it — so a `pool.query()` call from inside a `withTransaction` callback waits on the transaction it is part of and **deadlocks the request** (it hangs with no error). This includes indirect calls through a repository bound to the pool.

```javascript
await authRepo.withTransaction(async (txRepo) => {
  // Correct: txRepo wraps the client that holds the lock.
  await txRepo.insertAppSession(username, expiresAt, meta);

  // WRONG - deadlocks: authRepo is bound to the pool, which
  // waits for the lock this transaction is holding.
  // await authRepo.getUserProfileByUsername(username);

  // WRONG for the same reason:
  // await pool.query('SELECT 1');
});
```

Rule of thumb: inside the `withTransaction` callback, only touch the `txRepo` parameter — never `authRepo`, the pool, or anything else that reaches the pool. Queries against the pool are fine again once the callback returns.

(The Postgres backend has the same rule with a different failure mode: a `pool.query()` inside a transaction runs on a different pooled connection, silently outside the transaction.)

---

## Standard Architecture & Dual-Database Support for Host Applications

MBKAuthe exports its universal database primitives so that all applications in the ecosystem share a unified repository and database structure:

- **`PostgresAdapter`**: Database adapter wrapping `pg.Pool` that binds `postgresDialect` and standardizes client acquisition.
- **`SqliteAdapter` / `SqlitePool`**: Universal SQLite adapter wrapping `better-sqlite3` with FIFO transaction mutex, parameter coercion, and row normalization.
- **`BaseRepository`**: Foundation repository with transaction lifecycle, `setDb()`, query helpers, and dialect tokens.
- **`translatePgToSqlite`**: Automatic runtime SQL translator for PostgreSQL syntax (`$1`, `ANY($1)`, casts, `ILIKE`, `NOW()`, `to_char`, `gen_random_uuid`, etc.).
- **`postgresDialect` / `sqliteDialect`**: SQL tokens for quotes, placeholders, and pagination.
- **`applySchema`**: Centralized schema runner that applies `.sql` files or raw SQL statements to both SQLite adapters and PostgreSQL pools/adapters.
- **`registerGracefulShutdown` & `closeAllConnections`**: Centralized process signal hooks (`SIGINT`, `SIGTERM`) that cleanly close and drain connection pools on shutdown.

For the full directory conventions (`src/db/connection.js`, `src/db/index.js`, `src/db/schema/`, `src/repositories/`) and complete code walkthrough, see the **[Dual-Database & Repository Architecture Guide](dual-database-guide.md)**.

