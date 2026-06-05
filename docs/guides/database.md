# Database Schema

[Back to docs index](../README.md) | [Back to project README](../../README.md)

**Executable DDL lives only in [`docs/schema/db.sql`](../schema/db.sql).** This file explains what that script creates and how the app uses it. Run the script against Postgres when bootstrapping or aligning a database (for example `psql $DATABASE_URL -f docs/schema/db.sql`). The app can also apply it via `lib/createTable.js`, which reads `docs/schema/db.sql`.

---

## 1. Roles

Postgres enum `role`: `SuperAdmin`, `NormalUser`, `Guest`, `member`. The script creates the type only if it does not already exist. `Users."Role"` defaults to `NormalUser`.

---

## 2. Users

Core accounts table (`"Users"`): username, activation flag, role, mail flag, `AllowedApps` and `Positions` as JSONB, timestamps, optional `last_login`, and password hash column `PasswordEnc` (no plaintext passwords).

Profile-style columns include `FullName`, `email`, `Image`, `Bio`, `SocialAccounts`, and password-reset fields (`resetToken`, `resetTokenExpires`, `resetAttempts`, `lastResetAttempt`).

Indexes cover username, role, active, email, last login, and GIN indexes on JSONB for `AllowedApps` and `Positions`. The SQL file also adds optional covering indexes used on hot auth paths.

---

## 3. OAuth: `user_github` and `user_google`

Link rows from `"Users"("UserName")` to GitHub or Google identities (provider ids, usernames/emails, tokens, timestamps). `user_github` may be altered by the script to add `installation_id` and `installation_target_type` if missing (idempotent migrations).

---

## 4. Sessions

- **`"Sessions"`** — App session rows: UUID `id`, `UserName`, `created_at`, optional `expires_at`, optional `meta` JSONB. Requires `gen_random_uuid()` (e.g. `pgcrypto`). Extra indexes support expiry cleanup and middleware lookups.
- **`"session"`** — `express-session` Postgres store: `sid`, `sess` JSONB, `expire`, plus `username` and `last_activity` as in `db.sql`.

---

## 5. Two-factor: `TwoFA`

Per-user 2FA flag and secret, keyed by `UserName`.

---

## 6. Trusted devices: `TrustedDevices`

Remembered devices (token, optional name, user agent, IP, created/expires/last-used) to skip repeated 2FA when valid.

---

## 7. API tokens: `ApiTokens`

Named tokens per user: hash and prefix for lookup, optional expiry, `LastUsed`, and `Permissions` JSONB with constraints defined in SQL.

### `Permissions` shape (JSONB)

```json
{
  "scope": "read-only" | "write",
  "allowedApps": null | ["app1", "app2"] | ["*"] | []
}
```

- **`scope`:** `read-only` limits to safe methods (GET, HEAD, OPTIONS); `write` allows mutating methods.
- **`allowedApps`:** `null` inherits the user’s `AllowedApps` from `"Users"`; a string array restricts to those apps (subset of the user’s apps); `["*"]` means all of the user’s apps (SuperAdmin: system-wide); `[]` effectively disables app access.

SuperAdmin users bypass app checks in the app layer; token `allowedApps` still matters for non–SuperAdmin users.

---

## 8. Seed data

`db.sql` inserts a default `support` user with a precomputed hash (documented there). Change that password immediately in production.

---

## 9. Other tables in `db.sql`

- **`todos`** — Tasks keyed by `username` → `"Users"`, with type (`personal` / `admin`), completion, assignment fields, and several btree indexes for listing/filtering.
- **`plan_upgrade_requests`** — Role/plan upgrade workflow: requester, requested role/plan, reason, optional links, status (`pending` / `approved` / `rejected`), admin review fields, timestamps, and indexes for admin queues.

---

## Adding users without duplicating SQL

Use `hashPassword(password, username)` from the library so `PasswordEnc` matches login verification (username participates as salt input).

```javascript
import { hashPassword } from "mbkauthe";
const encryptedPassword = hashPassword("your-password", "newusername");
// INSERT ... "PasswordEnc" = encryptedPassword (see column list in db.sql)
```

Replace usernames, roles (`SuperAdmin`, `NormalUser`, `Guest`, `member`), and flags (`Active`, `HaveMailAccount`) to match your needs.
