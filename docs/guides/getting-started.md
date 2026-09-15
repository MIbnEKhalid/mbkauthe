# Getting Started with MBKAuthe v6

MBKAuthe is a developer-first authentication and authorization engine for Node.js and Express. It provides unified session management, dual-database persistence (PostgreSQL & SQLite), dynamic manifest-driven permissions (RBAC), cryptographic token creation, RFC 8628 CLI device flows, and domain event streaming.

---

## Prerequisites

- **Node.js**: `>= 18.0.0` (ESM module support)
- **Database**:
  - **PostgreSQL**: Version 13+ (when using `DB_TYPE=postgres`), OR
  - **SQLite**: Automatic zero-config embedded SQLite via `better-sqlite3` (when using `DB_TYPE=sqlite`).

---

## Installation

Install MBKAuthe and Express in your project:

```bash
npm install mbkauthe express
```

---

## 1. Environment Configuration

Create a `.env` file in the root of your project:

```env
APP_NAME=my_app
DOMAIN=localhost
IS_DEPLOYED=false
MAIN_SECRET_TOKEN=c8a7f92039e14a19b2e047395018f3a9e14a19b2e047395018f3a9e14a19b2e0
SESSION_SECRET_KEY=94e723910ab38c4719e048395029e14a19b2e047395018f3a9e14a19b2e04739
DB_TYPE=sqlite
SQLITE_PATH=./data/mbkauthe.sqlite
COOKIE_EXPIRE_TIME=2
LOGIN_REDIRECT_URL=/dashboard
MAX_SESSIONS_PER_USER=5
```

> [!TIP]
> Generate secure 32-byte (64 hex characters) secrets using `node -e "console.log(crypto.randomBytes(32).toString('hex'))"`.

---

## 2. Initialize Database Tables

To apply the database schema automatically before starting your application:

```typescript
import { applySchema, dblogin, dialect } from "mbkauthe/db";

async function initializeDatabase() {
  console.log(`Connecting to ${dialect.name} database...`);
  await applySchema(dblogin, dialect.name);
  console.log("Database schema initialized successfully.");
}

initializeDatabase();
```

---

## 3. Mount in Express Application

Mount MBKAuthe as a router or create the full application via the factory:

```typescript
import express from "express";
import mbkauthe, { sessVal, roleChk, sessPerm } from "mbkauthe";

const app = express();

// 1. Mount MBKAuthe authentication routes (/mbkauthe/*)
app.use(mbkauthe);

// 2. Public route
app.get("/", (req, res) => {
  res.json({ message: "Welcome to our application!" });
});

// 3. Protected user route
app.get("/dashboard", sessVal, (req, res) => {
  res.json({
    message: `Hello, ${req.session.user.username}!`,
    user: req.session.user,
  });
});

// 4. Role-protected admin route
app.get("/admin", sessVal, roleChk("superadmin"), (req, res) => {
  res.json({ message: "Welcome to the Superadmin Control Center" });
});

app.listen(3000, () => {
  console.log("Server listening on http://localhost:3000");
});
```

---

## 4. Key Architectural Concepts

```
┌──────────────────────────────────────────────────────────┐
│                   HTTP / Middleware Layer                │
│  sessVal │ roleChk │ sessPerm │ securityHeaders │ CORS   │
└────────────────────────────┬─────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────┐
│                       Domain Services                    │
│  AuthService │ ApiTokenService │ CliAuthService │ OAuth   │
└────────────────────────────┬─────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────┐
│                    Core Engine & Security                │
│  TokenEngine │ RoleRegistry │ Manifests │ Event Emitter  │
└────────────────────────────┬─────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────┐
│                  Database & Repository Layer             │
│  PostgresAdapter │ SqliteAdapter (WAL+Mutex) │ dbRetry   │
└──────────────────────────────────────────────────────────┘
```

- **Modular Repositories**: Pure data access models (`UserRepository`, `SessionRepository`, `AuthRepository`, `PermissionRepository`, etc.) with built-in SQL dialect safety.
- **Dynamic Manifest Permissions**: Define `app:service:action` permission scopes with `definePermissions` and sync them automatically with `syncAppPermissions`.
- **Cryptographic TokenEngine**: Prefixed Bearer tokens (`mbk_pat_`, `mbk_cli_`) with constant-time SHA-256 verification.
- **Observability & Health**: Listen to domain events via `authEvents` and inspect runtime status using `getAuthHealthReport()`.

---

## Next Steps

- Explore [Environment Configuration](configuration.md) for full configuration options.
- Learn about [Dual-Database Setup](database.md).
- Implement [Dynamic Permission Catalogs](permissions.md).
