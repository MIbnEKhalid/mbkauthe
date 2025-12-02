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
Main_SECRET_TOKEN=your-secure-token-number
SESSION_SECRET_KEY=your-secure-random-key-here
IS_DEPLOYED=false
DOMAIN=localhost
EncPass=false
```

#### Main_SECRET_TOKEN
**Description:** Primary authentication token for secure operations.

- **Security:** Use a secure numeric or alphanumeric token
- **Purpose:** Used for internal authentication and validation processes
- **Format:** Numeric or string value
- **Required:** Yes

**Example:** `Main_SECRET_TOKEN=123456789`

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

#### EncPass
**Description:** Controls whether passwords are stored and validated in encrypted format.

**Values:**
- `true` - Use encrypted password validation
  - Passwords are hashed using PBKDF2 with the username as salt
  - Compares against `PasswordEnc` column in Users table
- `false` - Use raw password validation (default)
  - Passwords are stored and compared in plain text
  - Compares against `Password` column in Users table

**Default:** `false`

**Security Note:** Setting `EncPass=true` is recommended for production environments as it provides better security by storing hashed passwords instead of plain text.

**Examples:**
```env
# Production (recommended)
EncPass=true

# Development
EncPass=false
```

**Database Implications:**
- When `EncPass=true`: The system uses the `PasswordEnc` column
- When `EncPass=false`: The system uses the `Password` column
- Ensure your database schema includes the appropriate column based on your configuration

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

## 🔄 Redirect Configuration

### Login Redirect URL
```env
loginRedirectURL=/mbkauthe/test
```

**Description:** Specifies the URL path where users are redirected after successful authentication.

- **Purpose:** Controls post-login navigation flow
- **Format:** URL path (relative or absolute)
- **Default:** `/` (root path if not specified)
- **Required:** No (optional configuration)

**Examples:**
```env
# Redirect to dashboard
loginRedirectURL=/dashboard

# Redirect to specific app section
loginRedirectURL=/mbkauthe/test

# Redirect to home page
loginRedirectURL=/

# Redirect to external URL (if supported)
loginRedirectURL=https://example.com/app
```

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
COOKIE_EXPIRE_TIME=7   # 7 days (balanced)
COOKIE_EXPIRE_TIME=30  # 30 days (convenience)
```

### Device Trust Duration
```env
DEVICE_TRUST_DURATION_DAYS=7
```

**Description:** Sets how long a device remains trusted after successful authentication.

- **Unit:** Days
- **Default:** `7` days
- **Purpose:** Controls device recognition and trust persistence
- **Range:** 1-365 days (recommended)
- **Behavior:** Trusted devices may skip certain authentication steps (like 2FA) during this period

**Examples:**
```env
DEVICE_TRUST_DURATION_DAYS=1   # 1 day (high security)
DEVICE_TRUST_DURATION_DAYS=7   # 1 week (balanced)
DEVICE_TRUST_DURATION_DAYS=30  # 30 days (convenience)
```

---

## 🐙 GitHub OAuth Authentication

### GitHub Login Configuration
```env
GITHUB_LOGIN_ENABLED=false
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

#### GITHUB_LOGIN_ENABLED
**Description:** Enables or disables GitHub OAuth login functionality.

**Values:**
- `true` - Enable GitHub login (users can authenticate via GitHub)
- `false` - Disable GitHub login (default)

**Required:** Yes (if using GitHub authentication)

#### GITHUB_CLIENT_ID
**Description:** OAuth application client ID from GitHub.

- **Purpose:** Identifies your application to GitHub's OAuth service
- **Format:** Alphanumeric string provided by GitHub
- **Setup:** Obtain from [GitHub Developer Settings](https://github.com/settings/developers)
- **Required:** Yes (when `GITHUB_LOGIN_ENABLED=true`)

**Example:** `GITHUB_CLIENT_ID=Iv1.a1b2c3d4e5f6g7h8`

#### GITHUB_CLIENT_SECRET
**Description:** OAuth application client secret from GitHub.

- **Purpose:** Authenticates your application with GitHub's OAuth service
- **Security:** Keep this secret secure and never commit to version control
- **Format:** Alphanumeric string provided by GitHub
- **Setup:** Generated when creating OAuth app in GitHub Developer Settings
- **Required:** Yes (when `GITHUB_LOGIN_ENABLED=true`)

**Example:** `GITHUB_CLIENT_SECRET=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0`

### Setting Up GitHub OAuth

1. **Create GitHub OAuth App:**
   - Go to [GitHub Developer Settings](https://github.com/settings/developers)
   - Click "New OAuth App"
   - Fill in application details:
     - **Application name:** Your app name
     - **Homepage URL:** `https://yourdomain.com` (or `http://localhost:3000` for dev)
     - **Authorization callback URL:** `https://yourdomain.com/auth/github/callback`
   - Click "Register application"

2. **Copy Credentials:**
   - Copy the **Client ID**
   - Generate and copy the **Client Secret**

3. **Configure Environment:**
   ```env
   GITHUB_LOGIN_ENABLED=true
   GITHUB_CLIENT_ID=your-copied-client-id
   GITHUB_CLIENT_SECRET=your-copied-client-secret
   ```

**Security Notes:**
- Use separate OAuth apps for development and production environments
- Rotate client secrets periodically
- Never expose client secrets in client-side code

---

## 🚀 Quick Setup Examples

### Development Environment
```env
# .env file for local development
APP_NAME=mbkauthe
Main_SECRET_TOKEN=dev-token-123
SESSION_SECRET_KEY=dev-secret-key-change-in-production
IS_DEPLOYED=false
DOMAIN=localhost
EncPass=false
LOGIN_DB=postgresql://admin:password@localhost:5432/mbkauth_dev
MBKAUTH_TWO_FA_ENABLE=false
COOKIE_EXPIRE_TIME=7
DEVICE_TRUST_DURATION_DAYS=7
loginRedirectURL=/dashboard
GITHUB_LOGIN_ENABLED=false
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
```

### Production Environment
```env
# .env file for production deployment
APP_NAME=mbkauthe
Main_SECRET_TOKEN=your-secure-production-token
SESSION_SECRET_KEY=your-super-secure-production-key-here
IS_DEPLOYED=true
DOMAIN=yourdomain.com
EncPass=true
LOGIN_DB=postgresql://dbuser:securepass@prod-db.example.com:5432/mbkauth_prod
MBKAUTH_TWO_FA_ENABLE=true
COOKIE_EXPIRE_TIME=2
DEVICE_TRUST_DURATION_DAYS=7
loginRedirectURL=/dashboard
GITHUB_LOGIN_ENABLED=false
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
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