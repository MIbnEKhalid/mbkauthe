# Environment Configuration Guide

[← Back to README](README.md)

This guide explains how to configure your MBKAuth application using environment variables. Create a `.env` file in your project root and set the following variables according to your deployment needs.

---

## 📱 Application Settings

### App Name Configuration
```env
APP_NAME=mbkauthe
```

**Description:** Defines the application identifier used for user access control.

- **Purpose:** Distinguishes this application from others in your ecosystem
- **Security:** Users are restricted to apps they're authorized for via the `AllowedApp` column in the Users table
- **Required:** Yes

---

## 🔐 Session Management

### Session Configuration
```env
SESSION_SECRET_KEY=your-secure-random-key-here
IS_DEPLOYED=false
DOMAIN=localhost
```

#### SESSION_SECRET_KEY
**Description:** Cryptographic key for session security.

- **Security:** Use a strong, randomly generated key (minimum 32 characters)
- **Generation:** Generate securely at [Generate Secret](https://generate-secret.vercel.app/32)
- **Example:** `SESSION_SECRET_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6`
- **Required:** Yes

#### IS_DEPLOYED
**Description:** Deployment environment flag that affects session behavior.

**Values:**
- `true` - Production/deployed environment
  - Sessions work across all subdomains of your specified domain
  - **Important:** Login will NOT work on `localhost` when set to `true`
- `false` - Local development environment
  - Sessions work on localhost for development

**Default:** `false`

#### DOMAIN
**Description:** Your application's domain name.

**Configuration:**
- **Production:** Set to your actual domain (e.g., `mbktech.com`)
- **Development:** Use `localhost` or set `IS_DEPLOYED=false`
- **Subdomains:** When `IS_DEPLOYED=true`, sessions are shared across all subdomains

**Examples:**
```env
# Production
DOMAIN=yourdomain.com
IS_DEPLOYED=true

# Development
DOMAIN=localhost
IS_DEPLOYED=false
```

---

## 🗄️ Database Configuration

### PostgreSQL Connection
```env
LOGIN_DB=postgresql://username:password@host:port/database_name
```

**Description:** PostgreSQL database connection string for user authentication.

**Format:** `postgresql://[username]:[password]@[host]:[port]/[database]`

**Examples:**
```env
# Local database
LOGIN_DB=postgresql://admin:password123@localhost:5432/mbkauth_db

# Remote database
LOGIN_DB=postgresql://user:pass@db.example.com:5432/production_db

# With SSL (recommended for production)
LOGIN_DB=postgresql://user:pass@host:5432/db?sslmode=require
```

**Required:** Yes

---

## 🔒 Two-Factor Authentication (2FA)

### 2FA Configuration
```env
MBKAUTH_TWO_FA_ENABLE=false
```

**Description:** Enables or disables Two-Factor Authentication for enhanced security.

**Values:**
- `true` - Enable 2FA (recommended for production)
- `false` - Disable 2FA (default)

**Note:** When enabled, users will need to configure an authenticator app (Google Authenticator, Authy, etc.) for login.

---

## 🍪 Cookie Settings

### Cookie Expiration
```env
COOKIE_EXPIRE_TIME=2
```

**Description:** Sets how long authentication cookies remain valid.

- **Unit:** Days
- **Default:** `2` days
- **Range:** 1-30 days (recommended)
- **Security:** Shorter periods are more secure but require more frequent logins

**Examples:**
```env
COOKIE_EXPIRE_TIME=1   # 1 day (high security)
COOKIE_EXPIRE_TIME=7   # 1 week (balanced)
COOKIE_EXPIRE_TIME=30  # 1 month (convenience)
```

---

## 🚀 Quick Setup Examples

### Development Environment
```env
# .env file for local development
APP_NAME=mbkauthe
SESSION_SECRET_KEY=dev-secret-key-change-in-production
IS_DEPLOYED=false
DOMAIN=localhost
LOGIN_DB=postgresql://admin:password@localhost:5432/mbkauth_dev
MBKAUTH_TWO_FA_ENABLE=false
COOKIE_EXPIRE_TIME=7
```

### Production Environment
```env
# .env file for production deployment
APP_NAME=mbkauthe
SESSION_SECRET_KEY=your-super-secure-production-key-here
IS_DEPLOYED=true
DOMAIN=yourdomain.com
LOGIN_DB=postgresql://dbuser:securepass@prod-db.example.com:5432/mbkauth_prod
MBKAUTH_TWO_FA_ENABLE=true
COOKIE_EXPIRE_TIME=2
```

---

## ⚠️ Important Security Notes

1. **Never commit your `.env` file** to version control
2. **Use strong, unique secrets** for production environments
3. **Enable HTTPS** when `IS_DEPLOYED=true`
4. **Regularly rotate** your `SESSION_SECRET_KEY`
5. **Use environment-specific databases** (separate dev/prod databases)
6. **Enable 2FA** for production environments

---

## 🔧 Troubleshooting

### Common Issues

**Login not working on localhost:**
- Ensure `IS_DEPLOYED=false` for local development
- Check that `DOMAIN=localhost`

**Session not persisting:**
- Verify `SESSION_SECRET_KEY` is set and consistent
- Check cookie settings in your browser

**Database connection errors:**
- Verify database credentials and connection string format
- Ensure database server is running and accessible

**2FA issues:**
- Confirm authenticator app time is synchronized
- Verify `MBKAUTH_TWO_FA_ENABLE` setting matches your setup