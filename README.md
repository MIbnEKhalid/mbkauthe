# MBKAuthe - Authentication System for Node.js

[![Version](https://img.shields.io/npm/v/mbkauthe.svg)](https://www.npmjs.com/package/mbkauthe)
[![License](https://img.shields.io/badge/License-GPL--2.0-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen.svg)](https://nodejs.org/)
[![Publish to npm](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/publish.yml/badge.svg?branch=main)](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/publish.yml)
[![CodeQL Advanced](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/codeql.yml)


<p align="center">
  <img height="64px" src="./public/icon.svg" alt="MBK Chat Platform" />
</p>

<p align="center">
  <img src="https://skillicons.dev/icons?i=nodejs,express,postgres" />
  <img height="48px" src="https://handlebarsjs.com/handlebars-icon.svg" alt="Handlebars" />
</p>

**MBKAuthe** is a production-ready authentication system for Node.js applications. Built with Express and PostgreSQL, it provides secure authentication, 2FA, role-based access, and OAuth integration (GitHub & Google) out of the box.

## ✨ Key Features

- 🔐 Secure password authentication with PBKDF2 hashing
- 🔑 PostgreSQL session management with cross-subdomain support
- 📱 Optional TOTP-based 2FA with trusted device memory
- 🔄 OAuth integration (GitHub & Google)
- 👥 Role-based access control (SuperAdmin, NormalUser, Guest)
- 🎯 Multi-application user management
- 🛡️ CSRF protection & advanced rate limiting
- 🚀 Easy Express.js integration
- 🎨 Customizable Handlebars templates
- 🔒 Enhanced security with session fixation prevention

## 📦 Installation

```bash
npm install mbkauthe
```

## 🚀 Quick Start

**1. Configure Environment (.env)**

```env
APP_NAME=your-app
SESSION_SECRET_KEY=your-secret-key
MAIN_SECRET_TOKEN=api-token
IS_DEPLOYED=false
DOMAIN=localhost
LOGIN_DB=postgresql://user:pass@localhost:5432/db

# Optional Features
MBKAUTH_TWO_FA_ENABLE=false
COOKIE_EXPIRE_TIME=2

# OAuth Configuration (Optional)
GITHUB_LOGIN_ENABLED=false
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

GOOGLE_LOGIN_ENABLED=false
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
```

**2. Set Up Database**

```sql
CREATE TYPE role AS ENUM ('SuperAdmin', 'NormalUser', 'Guest');

CREATE TABLE "Users" (
    id SERIAL PRIMARY KEY,
    "UserName" VARCHAR(50) NOT NULL UNIQUE,
    "Password" VARCHAR(61) NOT NULL,
    "Role" role DEFAULT 'NormalUser',
    "Active" BOOLEAN DEFAULT FALSE,
    "AllowedApps" JSONB DEFAULT '["mbkauthe"]',
    "SessionId" VARCHAR(213),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

See [docs/db.md](docs/db.md) for complete schemas.

**3. Integrate with Express**

```javascript
import express from 'express';
import mbkauthe, { validateSession, checkRolePermission } from 'mbkauthe';
import dotenv from 'dotenv';

dotenv.config();

// App-specific configuration (as JSON string)
process.env.mbkautheVar = JSON.stringify({
    APP_NAME: process.env.APP_NAME,
    SESSION_SECRET_KEY: process.env.SESSION_SECRET_KEY,
    Main_SECRET_TOKEN: process.env.MAIN_SECRET_TOKEN,
    IS_DEPLOYED: process.env.IS_DEPLOYED,
    DOMAIN: process.env.DOMAIN,
    LOGIN_DB: process.env.LOGIN_DB,
    loginRedirectURL: '/dashboard'
});

// Optional shared configuration (useful for shared OAuth credentials across multiple projects)
process.env.mbkauthShared = JSON.stringify({
    GITHUB_CLIENT_ID: process.env.GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET: process.env.GITHUB_CLIENT_SECRET,
    GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET
});

// MBKAuth prioritizes values in mbkautheVar, then mbkauthShared, then built-in defaults.

const app = express();

// Mount authentication routes
app.use(mbkauthe);

// Protected routes
app.get('/dashboard', validateSession, (req, res) => {
    res.send(`Welcome ${req.session.user.username}!`);
});

app.get('/admin', validateSession, checkRolePermission(['SuperAdmin']), (req, res) => {
    res.send('Admin Panel');
});

app.listen(3000);
```


## 🧪 Testing & Git Hooks

MBKAuthe includes comprehensive test coverage for all authentication features. **A pre-commit hook is provided to ensure code quality:**

### Pre-commit Hook (Automatic Test Runner)

- Located at `scripts/pre-commit` and `scripts/pre-commit` (Node.js, cross-platform)
- Starts the dev server, runs all tests, and blocks commits if any test fails
- The dev server is automatically stopped after tests complete
- Ensures you never commit code that breaks tests

### Git Hook Setup

Hooks are auto-configured every time you run `npm run dev`, `npm test`, or `npm run test:watch` (see `scripts/setup-hooks.js`).

If you ever need to manually set up hooks:

```bash
node scripts/setup-hooks.js
```

### Running Tests

```bash
# Run all tests (auto-configures hooks)
npm test

# Run tests in watch mode (auto-configures hooks)
npm run test:watch

# Run with development flags (auto-configures hooks)
npm run dev
```

**Test Coverage:**
- ✅ Authentication flows (login, 2FA, logout)
- ✅ OAuth integration (GitHub)
- ✅ Session management and security
- ✅ Role-based access control
- ✅ API endpoints and error handling
- ✅ CSRF protection and rate limiting
- ✅ Static asset serving

## 📂 Architecture (v3.0)

```
lib/
├── config/          # Configuration & security
├── database/        # PostgreSQL pool
├── utils/           # Errors & response helpers
├── middleware/      # Auth & session middleware
└── routes/          # Auth, OAuth, misc routes
```

**Key Improvements in v3.0:**
- Modular structure with clear separation of concerns
- Organized config, database, utils, middleware, and routes
- Better maintainability and scalability

## 🔧 Core API

### Middleware

```javascript
// Session validation
app.get('/protected', validateSession, handler);

// Role checking
app.get('/admin', validateSession, checkRolePermission(['SuperAdmin']), handler);

// Combined
import { validateSessionAndRole } from 'mbkauthe';
app.get('/mod', validateSessionAndRole(['SuperAdmin', 'NormalUser']), handler);

// API token auth
import { authenticate } from 'mbkauthe';
app.post('/api/data', authenticate(process.env.API_TOKEN), handler);
```

### Built-in Routes

**Authentication Routes:**
- `GET /login`, `/signin` - Redirect to main login page
- `GET /mbkauthe/login` - Login page (8/min rate limit)
- `POST /mbkauthe/api/login` - Login endpoint (8/min rate limit)
- `POST /mbkauthe/api/logout` - Logout endpoint (10/min rate limit)
- `GET /mbkauthe/2fa` - 2FA verification page (if enabled)
- `POST /mbkauthe/api/verify-2fa` - 2FA verification API (5/min rate limit)

**OAuth Routes:**
- `GET /mbkauthe/api/github/login` - GitHub OAuth initiation (10/5min rate limit)
- `GET /mbkauthe/api/github/login/callback` - GitHub OAuth callback
- `GET /mbkauthe/api/google/login` - Google OAuth initiation (10/5min rate limit)
- `GET /mbkauthe/api/google/login/callback` - Google OAuth callback

**Information & Utility Routes:**
- `GET /mbkauthe/info`, `/mbkauthe/i` - Version & config info (8/min rate limit)
- `GET /mbkauthe/ErrorCode` - Error code documentation
- `GET /mbkauthe/test` - Test authentication status (8/min rate limit)

**Static Asset Routes:**
- `GET /mbkauthe/main.js` - Client-side JavaScript utilities
- `GET /mbkauthe/bg.webp` - Background image for auth pages
- `GET /icon.svg` - Application SVG icon (root level)
- `GET /favicon.ico`, `/icon.ico` - Application favicon

**Admin API Routes:**
- `POST /mbkauthe/api/terminateAllSessions` - Terminate all sessions (admin only)

## 🔐 Security Features

- **Rate Limiting**: Login (8/min), Logout (10/min), 2FA (5/min), OAuth (10/5min), Admin (3/5min)
- **CSRF Protection**: All state-changing routes protected with token validation
- **Secure Cookies**: httpOnly, sameSite, secure in production
- **Password Hashing**: PBKDF2 with 100k iterations
- **Session Security**: PostgreSQL-backed, automatic cleanup, session fixation prevention
- **OAuth Security**: State validation, token expiry handling, secure callback validation

## 📱 Two-Factor Authentication

Enable with `MBKAUTH_TWO_FA_ENABLE=true`:

```sql
CREATE TABLE "TwoFA" (
    "UserName" VARCHAR(50) PRIMARY KEY REFERENCES "Users"("UserName"),
    "TwoFAStatus" BOOLEAN NOT NULL,
    "TwoFASecret" TEXT
);
```

Users can mark devices as trusted to skip 2FA for configurable duration.

## 🔄 OAuth Integration

### GitHub OAuth

**Setup:**

1. Create GitHub OAuth App with callback: `https://yourdomain.com/mbkauthe/api/github/login/callback`
2. Configure environment:
```env
GITHUB_LOGIN_ENABLED=true
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret
```
3. Create table:
```sql
CREATE TABLE user_github (
    id SERIAL PRIMARY KEY,
    user_name VARCHAR(50) REFERENCES "Users"("UserName"),
    github_id VARCHAR(255) UNIQUE,
    github_username VARCHAR(255),
    access_token VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);
```

### Google OAuth

**Setup:**

1. Create Google OAuth 2.0 Client in [Google Cloud Console](https://console.cloud.google.com/)
2. Add authorized redirect URI: `https://yourdomain.com/mbkauthe/api/google/login/callback`
3. Configure environment:
```env
GOOGLE_LOGIN_ENABLED=true
GOOGLE_CLIENT_ID=your_client_id
GOOGLE_CLIENT_SECRET=your_client_secret
```
4. Create table:
```sql
CREATE TABLE user_google (
    id SERIAL PRIMARY KEY,
    user_name VARCHAR(50) REFERENCES "Users"("UserName"),
    google_id VARCHAR(255) UNIQUE,
    google_email VARCHAR(255),
    access_token VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);
```

**Note:** Users must link their OAuth accounts before they can use OAuth login.

## 🎨 Customization

**Redirect URL:**
```javascript
process.env.mbkautheVar = JSON.stringify({
    // ...
    loginRedirectURL: '/dashboard'
});
```

**Custom Views:** Create in `views/` directory:
- `loginmbkauthe.handlebars` - Login page
- `2fa.handlebars` - 2FA page
- `Error/dError.handlebars` - Error page

**Database Access:**
```javascript
import { dblogin } from 'mbkauthe';
const result = await dblogin.query('SELECT * FROM "Users"');
```

## 🚢 Deployment

**Production Checklist:**
- ✅ Set `IS_DEPLOYED=true`
- ✅ Use strong secrets for SESSION_SECRET_KEY and Main_SECRET_TOKEN
- ✅ Enable HTTPS
- ✅ Configure correct DOMAIN
- ✅ Set appropriate COOKIE_EXPIRE_TIME
- ✅ Use environment variables for all secrets

**Vercel:**

Tip: On Vercel you can set `mbkauthShared` at the project or team level to share common OAuth credentials across multiple deployments. MBKAuth will use values from `mbkautheVar` first and fall back to `mbkauthShared`.
```json
{
    "version": 2,
    "builds": [{ "src": "index.js", "use": "@vercel/node" }],
    "routes": [{ "src": "/(.*)", "dest": "/index.js" }]
}
```

## 📚 Documentation

- [API Documentation](docs/api.md) - Complete API reference
- [Database Guide](docs/db.md) - Schema details  
- [Environment Config](docs/env.md) - Configuration options
- [Error Messages](docs/error-messages.md) - Error code reference

## 📝 License

GNU General Public License v2.0 - see [LICENSE](LICENSE)

## 👨‍💻 Author

**Muhammad Bin Khalid**  
📧 [support@mbktech.org](mailto:support@mbktech.org) | [chmuhammadbinkhalid28@gmail.com](mailto:chmuhammadbinkhalid28@gmail.com)  
🔗 [@MIbnEKhalid](https://github.com/MIbnEKhalid)

## 🔗 Links

- [npm Package](https://www.npmjs.com/package/mbkauthe)
- [GitHub Repository](https://github.com/MIbnEKhalid/mbkauthe)
- [Issues & Support](https://github.com/MIbnEKhalid/mbkauthe/issues)

---

Made with ❤️ by [MBKTech.org](https://mbktech.org)