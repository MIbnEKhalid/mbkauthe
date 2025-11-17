# MBKAuthe - Authentication System for Node.js

[![Version](https://img.shields.io/npm/v/mbkauthe.svg)](https://www.npmjs.com/package/mbkauthe)
[![License](https://img.shields.io/badge/License-MPL--2.0-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen.svg)](https://nodejs.org/)
[![Publish to npm](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/publish.yml/badge.svg?branch=main)](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/publish.yml)
[![CodeQL Advanced](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/codeql.yml)

**MBKAuth** is a reusable, production-ready authentication system for Node.js applications built by MBKTechStudio. It provides secure session management, two-factor authentication (2FA), role-based access control, and multi-application support out of the box.

## ✨ Features

- 🔐 **Secure Authentication** - Password hashing with bcrypt
- 🔑 **Session Management** - PostgreSQL-backed session storage
- 📱 **Two-Factor Authentication (2FA)** - Optional TOTP-based 2FA with speakeasy
- 👥 **Role-Based Access Control** - SuperAdmin, NormalUser, and Guest roles
- 🎯 **Multi-Application Support** - Control user access across multiple apps
- 🛡️ **Security Features** - CSRF protection, rate limiting, secure cookies
- 🌐 **Subdomain Session Sharing** - Sessions work across all subdomains
- 🚀 **Easy Integration** - Drop-in authentication for Express.js apps
- 📊 **Database-Driven** - PostgreSQL for user and session management
- 🎨 **Customizable Views** - Handlebars templates for login/2FA pages

## 📦 Installation

```bash
npm install mbkauthe
```

## 🚀 Quick Start

### 1. Set Up Environment Variables

Create a `.env` file in your project root:

```env
# Application Configuration
APP_NAME=your-app-name
SESSION_SECRET_KEY=your-secure-random-secret-key
IS_DEPLOYED=false
DOMAIN=localhost

# Database Configuration
LOGIN_DB=postgresql://username:password@localhost:5432/database_name

# Optional Features
MBKAUTH_TWO_FA_ENABLE=false
COOKIE_EXPIRE_TIME=2
```

For detailed environment configuration, see [Environment Configuration Guide](env.md).

### 2. Set Up Database

Create the required tables in your PostgreSQL database. See [Database Structure Documentation](docs/db.md) for complete schemas.

```sql
-- Users table
CREATE TYPE role AS ENUM ('SuperAdmin', 'NormalUser', 'Guest');

CREATE TABLE "Users" (
    id SERIAL PRIMARY KEY,
    "UserName" VARCHAR(50) NOT NULL UNIQUE,
    "Password" VARCHAR(61) NOT NULL,
    "Role" role DEFAULT 'NormalUser' NOT NULL,
    "Active" BOOLEAN DEFAULT FALSE,
    "AllowedApps" JSONB DEFAULT '["mbkauthe"]',
    "SessionId" VARCHAR(213),
    "created_at" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Session table (created automatically by connect-pg-simple)
-- TwoFA table (optional, if 2FA is enabled)
```

### 3. Integrate with Your Express App

```javascript
import express from 'express';
import mbkauthe from 'mbkauthe';
import { validateSession, checkRolePermission } from 'mbkauthe';
import dotenv from 'dotenv';

dotenv.config();

// Set mbkauthe configuration
process.env.mbkautheVar = JSON.stringify({
    APP_NAME: process.env.APP_NAME,
    SESSION_SECRET_KEY: process.env.SESSION_SECRET_KEY,
    IS_DEPLOYED: process.env.IS_DEPLOYED,
    DOMAIN: process.env.DOMAIN,
    LOGIN_DB: process.env.LOGIN_DB,
    MBKAUTH_TWO_FA_ENABLE: process.env.MBKAUTH_TWO_FA_ENABLE,
    COOKIE_EXPIRE_TIME: process.env.COOKIE_EXPIRE_TIME || 2,
    loginRedirectURL: '/dashboard' // Redirect after successful login
});

const app = express();

// Mount MBKAuth routes
app.use(mbkauthe);

// Protected route example
app.get('/dashboard', validateSession, (req, res) => {
    res.send(`Welcome ${req.session.user.username}!`);
});

// Role-based route protection
app.get('/admin', validateSession, checkRolePermission(['SuperAdmin']), (req, res) => {
    res.send('Admin panel');
});

app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
```

## 🔧 API Reference

### Middleware Functions

#### `validateSession`
Validates that a user has an active session. Redirects to login if not authenticated.

```javascript
app.get('/protected', validateSession, (req, res) => {
    // User is authenticated
    console.log(req.session.user); // { id, username, role, sessionId }
});
```

#### `checkRolePermission(allowedRoles)`
Checks if the authenticated user has one of the allowed roles.

```javascript
app.get('/admin', validateSession, checkRolePermission(['SuperAdmin']), (req, res) => {
    // Only SuperAdmin can access
});
```

#### `validateSessionAndRole(allowedRoles)`
Combined middleware for session validation and role checking.

```javascript
app.get('/moderator', validateSessionAndRole(['SuperAdmin', 'NormalUser']), (req, res) => {
    // SuperAdmin or NormalUser can access
});
```

#### `authenticate(token)`
API authentication middleware using a secret token.

```javascript
app.post('/api/data', authenticate(process.env.API_TOKEN), (req, res) => {
    // Authenticated API request
});
```

### Routes Provided

MBKAuth automatically adds these routes to your app:

- `GET /mbkauthe/login` - Login page
- `POST /mbkauthe/api/login` - Login endpoint
- `POST /mbkauthe/api/logout` - Logout endpoint
- `GET /mbkauthe/2fa` - Two-factor authentication page (if enabled)
- `POST /mbkauthe/api/verify-2fa` - 2FA verification endpoint
- `GET /mbkauthe/info` - MBKAuth version and configuration info
- `POST /mbkauthe/api/terminateAllSessions` - Terminate all active sessions (authenticated)

## 🔐 Security Features

### Rate Limiting
- **Login attempts**: 8 attempts per minute
- **Logout attempts**: 10 attempts per minute
- **2FA attempts**: 5 attempts per minute

### CSRF Protection
All POST routes are protected with CSRF tokens. CSRF tokens are automatically included in rendered forms.

### Password Hashing
Passwords are hashed using bcrypt with a secure salt. Set `EncryptedPassword: "true"` in `mbkautheVar` to enable.

### Secure Cookies
- `httpOnly` flag prevents XSS attacks
- `sameSite: 'lax'` prevents CSRF attacks
- `secure` flag in production ensures HTTPS-only cookies
- Configurable expiration time

### Session Management
- PostgreSQL-backed persistent sessions
- Automatic session cleanup
- Session restoration from cookies
- Cross-subdomain session sharing (when deployed)

## 📱 Two-Factor Authentication

Enable 2FA by setting `MBKAUTH_TWO_FA_ENABLE=true` in your environment:

1. User logs in with username/password
2. If 2FA is enabled for the user, they're prompted for a 6-digit code
3. Code is verified using TOTP (Time-based One-Time Password)
4. Session is established after successful 2FA

### Database Setup for 2FA

```sql
CREATE TABLE "TwoFA" (
    "UserName" VARCHAR(50) PRIMARY KEY REFERENCES "Users"("UserName"),
    "TwoFAStatus" BOOLEAN NOT NULL,
    "TwoFASecret" TEXT
);
```

## 🎨 Customization

### Custom Login Redirect
Set `loginRedirectURL` in `mbkautheVar`:

```javascript
process.env.mbkautheVar = JSON.stringify({
    // ... other config
    loginRedirectURL: '/dashboard' // Redirect after login
});
```

### Custom Views
Override default views by creating files in your project's `views` directory:
- `views/loginmbkauthe.handlebars` - Login page
- `views/2fa.handlebars` - 2FA page
- `views/Error/dError.handlebars` - Error page

### Database Pool Access
Access the database pool for custom queries:

```javascript
import { dblogin } from 'mbkauthe';

const result = await dblogin.query('SELECT * FROM "Users" WHERE "UserName" = $1', [username]);
```

## 🚢 Deployment

### Vercel Deployment

Add `vercel.json`:

```json
{
    "version": 2,
    "builds": [
        {
            "src": "index.js",
            "use": "@vercel/node"
        }
    ],
    "routes": [
        {
            "src": "/(.*)",
            "dest": "/index.js"
        }
    ]
}
```

### Production Checklist

- [ ] Set `IS_DEPLOYED=true`
- [ ] Use a strong `SESSION_SECRET_KEY`
- [ ] Enable HTTPS
- [ ] Set correct `DOMAIN`
- [ ] Enable 2FA for sensitive applications
- [ ] Use environment variables for secrets
- [ ] Set appropriate `COOKIE_EXPIRE_TIME`
- [ ] Configure PostgreSQL with proper security
- [ ] Enable password hashing with bcrypt

## 📚 Documentation

- [API Documentation](docs/api.md) - Complete API reference and examples
- [Environment Configuration Guide](env.md) - Environment variables and setup
- [Database Structure](docs/db.md) - Database schemas and tables

## 🔄 Version Check

MBKAuth automatically checks for updates on startup and warns if a newer version is available. Keep your package updated for security patches.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the Mozilla Public License 2.0 - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Muhammad Bin Khalid**  
Email: [support@mbktechstudio.com](support@mbktechstudio.com) or [chmuhammadbinkhalid28@gmail.com](mailto:chmuhammadbinkhalid28@gmail.com)
GitHub: [@MIbnEKhalid](https://github.com/MIbnEKhalid)

## 🐛 Issues & Support

Found a bug or need help? Please [open an issue](https://github.com/MIbnEKhalid/mbkauthe/issues) on GitHub.

## 🔗 Links

- [npm Package](https://www.npmjs.com/package/mbkauthe)
- [GitHub Repository](https://github.com/MIbnEKhalid/mbkauthe)
- [MBKTechStudio](https://mbktechstudio.com)

---

Made with ❤️ by [MBKTechStudio](https://mbktechstudio.com)