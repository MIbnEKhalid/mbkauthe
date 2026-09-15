# Getting Started with MBKAuthe v6

MBKAuthe is a developer-first authentication and authorization engine for Node.js and Express. It provides unified session management, dual-database persistence (PostgreSQL & SQLite), provider-neutral OAuth 2.0 & OIDC, dynamic manifest-driven permissions (RBAC), decoupled authorization policies, cryptographic token creation, RFC 8628 CLI device flows, and domain event streaming.

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
import mbkauthe, { sessVal, sessRole, sessPerm } from "mbkauthe";
import { definePermissions } from "mbkauthe/core";
import { syncAppPermissions } from "mbkauthe/services";

const app = express();

// 1. Define App Permissions & Roles
const AppPermissions = definePermissions({
  appKey: "my_app",
  permissions: {
    dashboard: { view: "View main analytics dashboard" },
    admin: { manage: "Manage system configuration" },
  },
  roles: {
    superadmin: ["my_app:*"],
    normaluser: ["my_app:dashboard:view"],
  },
});

// 2. Mount MBKAuthe authentication routes (/mbkauthe/*)
app.use(mbkauthe);

// 3. Public route
app.get("/", (req, res) => {
  res.json({ message: "Welcome to our application!" });
});

// 4. Protected user route (Session or Bearer token)
app.get("/dashboard", sessVal, (req, res) => {
  res.json({
    message: `Hello, ${req.session.user.username}!`,
    user: req.session.user,
    auth: (req as any).auth,
  });
});

// 5. Role-protected admin route
app.get("/admin", sessRole("superadmin"), (req, res) => {
  res.json({ message: "Welcome to the Superadmin Control Center" });
});

// 6. Permission-protected route
app.get("/admin/config", sessPerm(AppPermissions.admin.manage), (req, res) => {
  res.json({ config: { maintenanceMode: false } });
});

// 7. Start Server and Sync Permissions
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  await syncAppPermissions(AppPermissions);
  console.log(`Server listening on http://localhost:${PORT}`);
});
```

---

## 4. Key Architectural Concepts

```
┌──────────────────────────────────────────────────────────┐
│                   HTTP / Middleware Layer                │
│  sessVal │ sessRole │ sessPerm │ roleChk │ permChk │ CORS│
└────────────────────────────┬─────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────┐
│                       Domain Services                    │
│  AuthService │ AuthorizationService │ ApiToken │ OAuth   │
└────────────────────────────┬─────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────┐
│                    Core Engine & Security                │
│  AuthContext │ TokenEngine │ RoleRegistry │ authEvents   │
└────────────────────────────┬─────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────┐
│                  Database & Repository Layer             │
│  PostgresAdapter │ SqliteAdapter (WAL+Mutex) │ dbRetry   │
└──────────────────────────────────────────────────────────┘
```

- **Modular Repositories**: Pure data access models (`UserRepository`, `SessionRepository`, `AuthRepository`, `PermissionRepository`, `ApiTokenRepository`, `OAuthAccountRepository`) with built-in SQL dialect safety.
- **Provider-Neutral OAuth & OIDC**: Modern social login architecture supporting Google, GitHub, Microsoft, Discord, Apple, and Custom OIDC with PKCE and token encryption.
- **Dynamic Manifest Permissions**: Define `app:service:action` permission scopes with `definePermissions` and sync them automatically with `syncAppPermissions`.
- **Decoupled Authorization**: Evaluate roles, permissions, and custom policies cleanly using `authorizationService` and `AuthContext`.
- **Cryptographic TokenEngine**: Prefixed Bearer tokens (`mbk_pat_`, `mbk_cli_`, `mbk_dev_`, `mbk_sess_`) with constant-time SHA-256 verification.
- **Observability & Health**: Listen to domain events via `authEvents` and inspect runtime status using `getAuthHealthReport()`.

---

## Next Steps

- Explore [Environment Configuration](configuration.md) for full configuration options.
- Learn about [Dual-Database Setup](database.md).
- Integrate [Provider-Neutral OAuth & OIDC](oauth.md).
- Implement [Dynamic Permission Catalogs](permissions.md).
