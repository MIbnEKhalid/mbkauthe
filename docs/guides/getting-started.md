# Getting Started with MBKAuthe

[Back to docs index](../README.md) | [Back to project README](../../README.md)

**MBKAuthe** is MBKTech's reusable authentication and session management system for Node.js and Express applications. It provides battle-tested security primitives, dual-database flexibility with PostgreSQL and SQLite, OAuth2 integration, Two-Factor Authentication, and RFC 8628 CLI device logins.

---

## Key Capabilities

- **Express Middleware**: Seamless session validation, role enforcement, and token checks.
- **Dual-Database Storage**: Native PostgreSQL connection pooling and SQLite support via `better-sqlite3` with WAL mode.
- **Strong Cryptography**: Password hashing via PBKDF2 with unique salts, AES encrypted session cookies.
- **Two-Factor Authentication**: TOTP (RFC 6238) compatible with Google Authenticator, Authy, and 1Password with device trust periods.
- **OAuth Providers**: Social sign-on with GitHub App and Google OAuth2.
- **API Tokens**: Bearer tokens with `mbk_` prefix, SHA-256 storage hashing, and read/write scoping.
- **CLI Device Flow**: Browser-based authentication for CLI tools and automation.
- **Multi-Session Management**: Concurrent session tracking and automated stale session eviction.

---

## Prerequisites

- **Node.js**: Version `18.0.0` or higher
- **Framework**: Express 4.x or 5.x
- **Database Backend**:
  - **PostgreSQL**: PostgreSQL 12+ (local or hosted e.g. Neon, AWS RDS)
  - **SQLite**: Local file path (no database server required)

---

## Installation

Install `mbkauthe` via npm or link it locally in workspace repositories:

```bash
# Production installation
npm install mbkauthe

# Or in MBKTech workspace
npm install latest
```

---

## Quick Start Mounting Example

Below is a complete Express application integrating MBKAuthe authentication:

```javascript
import express from "express";
import session from "express-session";
import cookieParser from "cookie-parser";
import { sessRole, sessVal, roleChk, authRouter } from "mbkauthe";

const app = express();

// Required middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET_KEY || "dev-secret-key-32-chars-long",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.IS_DEPLOYED === "true",
      httpOnly: true,
      sameSite: "lax",
    },
  })
);

// Mount MBKAuthe core routes (login, logout, 2FA, OAuth, CLI device flows)
app.use("/mbkauthe", authRouter);

// Public route
app.get("/", (req, res) => {
  res.send("<h1>Welcome to MBKTech App</h1><a href='/mbkauthe/login'>Login</a>");
});

// Protected route (requires active session)
app.get("/dashboard", sessVal, (req, res) => {
  res.json({
    message: "Welcome to dashboard",
    user: req.session.user,
  });
});

// Admin-only route (requires superadmin role)
app.get("/admin", sessRole("superadmin"), (req, res) => {
  res.json({
    message: "Welcome Superadmin",
    user: req.session.user,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
```

---

## Next Steps

Explore the detailed topic guides:

- [Environment Configuration Guide](configuration.md)
- [PostgreSQL & SQLite Dual Database Guide](dual-database-guide.md)
- [Role-Based Access Control (RBAC)](rbac.md)
- [Social OAuth Integration](oauth.md)
- [Two-Factor Authentication (2FA)](2fa.md)
- [REST API Reference](../reference/api.md)
