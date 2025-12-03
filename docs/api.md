# MBKAuthe API Documentation

[← Back to README](../README.md)

This document provides comprehensive API documentation for MBKAuthe authentication system.

---

## Table of Contents

- [Authentication](#authentication)
- [Session Management](#session-management)
- [API Endpoints](#api-endpoints)
  - [Public Endpoints](#public-endpoints)
  - [Protected Endpoints](#protected-endpoints)
  - [OAuth Endpoints](#oauth-endpoints)
  - [Information Endpoints](#information-endpoints)
- [Middleware Reference](#middleware-reference)
- [Code Examples](#code-examples)

---

## Authentication

MBKAuthe supports two authentication methods:

1. **Session-based Authentication** - Cookie-based sessions for web applications
2. **Token-based Authentication** - API key authentication for server-to-server communication

---

## Session Management

### Session Cookie

When a user logs in, MBKAuthe creates a session and sets the following cookies:

| Cookie Name | Description | HttpOnly | Secure | SameSite |
|------------|-------------|----------|--------|----------|
| `mbkauthe.sid` | Session identifier | ✓ | Auto* | lax |
| `sessionId` | User session ID | ✓ | Auto* | lax |
| `username` | Username | ✗ | Auto* | lax |

\* `secure` flag is automatically set to `true` in production when `IS_DEPLOYED=true`

### Session Lifetime

- Default: 2 days (configurable via `COOKIE_EXPIRE_TIME`)
- Sessions are stored in PostgreSQL
- Sessions persist across subdomains in production

---

## API Endpoints

### Public Endpoints

#### `GET /mbkauthe/login`

Renders the login page.

**Query Parameters:**
- `redirect` (optional) - URL to redirect after successful login

**Response:** HTML page

**Example:**
```
GET /mbkauthe/login?redirect=/dashboard
```

---

#### `POST /mbkauthe/api/login`

Authenticates a user and creates a session.

**Rate Limit:** 8 requests per minute

**Request Body:**
```json
{
  "username": "string (required, 1-255 chars)",
  "password": "string (required, 8-255 chars)"
}
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Login successful",
  "sessionId": "64-character-hex-string"
}
```

**Success Response with 2FA (200 OK):**
```json
{
  "success": true,
  "twoFactorRequired": true
}
```

**Error Responses:**

| Status Code | Message |
|------------|------------|---------|
| 400 | Username and password are required |
| 400 | Invalid username format |
| 400 | Password must be at least 8 characters long |
| 401 | Incorrect Username Or Password |
| 403 | Account is inactive |
| 403 | You Are Not Authorized To Use The Application |
| 404 | Incorrect Username Or Password |
| 429 | Too many attempts, please try again later |
| 500 | 605 | Internal Server Error |

**Example Request:**
```javascript
fetch('/mbkauthe/api/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    username: 'john.doe',
    password: 'securePassword123'
  })
})
.then(response => response.json())
.then(data => {
  if (data.success && data.twoFactorRequired) {
    // Redirect to 2FA page
    window.location.href = '/mbkauthe/2fa';
  } else if (data.success) {
    // Login successful
    window.location.href = data.redirectUrl || '/dashboard';
  }
});
```

---

#### `GET /mbkauthe/2fa`

Renders the Two-Factor Authentication verification page.

**Prerequisites:** User must have completed initial login with valid credentials

**Response:** HTML page

**Note:** Redirects to `/mbkauthe/login` if no pre-authentication session exists

---

#### `POST /mbkauthe/api/verify-2fa`

Verifies the 2FA token and completes the login process.

**Rate Limit:** 5 requests per minute

**CSRF Protection:** Required (token must be included)

**Request Body:**
```json
{
  "token": "string (required, 6-digit numeric code)",
  "_csrf": "string (required, CSRF token)"
}
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Login successful",
  "sessionId": "64-character-hex-string",
  "redirectUrl": "/dashboard"
}
```

**Error Responses:**

| Status Code | Message |
|------------|---------|
| 400 | 2FA token is required |
| 400 | Invalid 2FA token format |
| 401 | Not authorized. Please login first. |
| 401 | Invalid 2FA code |
| 429 | Too many 2FA attempts, please try again later |
| 500 | 2FA is not configured correctly. |
| 500 | Internal Server Error |

**Example Request:**
```javascript
fetch('/mbkauthe/api/verify-2fa', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    token: '123456',
    _csrf: csrfToken
  })
})
.then(response => response.json())
.then(data => {
  if (data.success) {
    window.location.href = data.redirectUrl;
  }
});
```

---

### Protected Endpoints

#### `POST /mbkauthe/api/logout`

Logs out the current user and destroys the session.

**Rate Limit:** 10 requests per minute

**CSRF Protection:** Required

**Authentication:** Session required

**Request Body:**
```json
{
  "_csrf": "string (required, CSRF token)"
}
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Logout successful"
}
```

**Error Responses:**

| Status Code | Message |
|------------|---------|
| 400 | Not logged in |
| 429 | Too many logout attempts, please try again later |
| 500 | Logout failed |
| 500 | Internal Server Error |

**Example Request:**
```javascript
fetch('/mbkauthe/api/logout', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    _csrf: csrfToken
  })
})
.then(response => response.json())
.then(data => {
  if (data.success) {
    window.location.href = '/mbkauthe/login';
  }
});
```

---

#### `POST /mbkauthe/api/terminateAllSessions`

Terminates all active sessions across all users (admin only).

**Authentication:** API token required

**Headers:**
```
Authorization: your-api-token
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "All sessions terminated successfully"
}
```

**Error Responses:**

| Status Code | Message |
|------------|---------|
| 401 | Unauthorized |
| 500 | Failed to terminate sessions |
| 500 | Internal Server Error |

**Example Request:**
```javascript
fetch('/mbkauthe/api/terminateAllSessions', {
  method: 'POST',
  headers: {
    'Authorization': 'your-secret-token',
  }
})
.then(response => response.json())
.then(data => console.log(data));
```

---

### Information Endpoints

#### `GET /mbkauthe/info`

Displays MBKAuthe version information and configuration.

**Aliases:** `/mbkauthe/i`

**Rate Limit:** 8 requests per minute

**Response:** HTML page showing:
- Current version
- Latest available version
- Configuration settings (sanitized)
- Update notification if newer version available

---

#### `GET /mbkauthe/ErrorCode`

Displays comprehensive error code documentation with descriptions and user messages.

**Response:** HTML page showing:
- All error codes organized by category
- Error code ranges (Authentication, 2FA, Session, Authorization, etc.)
- User-friendly messages and hints for each error
- Dynamically generated from `lib/utils/errors.js`

**Categories:**
- **600-699**: Authentication Errors
- **700-799**: Two-Factor Authentication Errors
- **800-899**: Session Management Errors
- **900-999**: Authorization Errors
- **1000-1099**: Input Validation Errors
- **1100-1199**: Rate Limiting Errors
- **1200-1299**: Server Errors
- **1300-1399**: OAuth Errors

**Note:** This page is automatically synchronized with the error definitions in the codebase. Adding new errors only requires updating `lib/utils/errors.js` and the category code array.

**Usage:**
```
GET /mbkauthe/ErrorCode
```

---

#### `GET /mbkauthe/main.js`

Serves the client-side JavaScript file containing helper functions for authentication operations.

**Purpose:** Provides frontend JavaScript utilities including:
- `logout()` - Logout function with confirmation dialog and cache clearing
- `logoutuser()` - Alias for logout function
- `nuclearCacheClear()` - Comprehensive cache and storage clearing (preserves rememberedUsername)
- `getCookieValue(cookieName)` - Cookie retrieval helper
- `loadpage(url)` - Page navigation helper
- `formatDate(date)` - Date formatting utility
- `reloadPage()` - Page reload helper
- `checkSession()` - Session validity checker

**Response:** JavaScript file (Content-Type: application/javascript)

**Usage:**
```html
<script src="/mbkauthe/main.js"></script>
<button onclick="logout()">Logout</button>
```

**Main Functions:**

**`logout()`**
- Shows confirmation dialog before logout
- Clears all caches except rememberedUsername
- Calls `/mbkauthe/api/logout` endpoint
- Redirects to home page on success

**`nuclearCacheClear()`**
- Clears service workers and cache storage
- Clears localStorage and sessionStorage (preserves rememberedUsername)
- Clears IndexedDB
- Clears cookies
- Forces page reload


---

#### `GET /mbkauthe/ErrorCode`

Displays comprehensive error code documentation with descriptions and user messages.

**Response:** HTML page showing:
- All error codes organized by category
- Error code ranges (Authentication, 2FA, Session, Authorization, etc.)
- User-friendly messages and hints for each error
- Dynamically generated from `lib/utils/errors.js`

**Categories:**
- **600-699**: Authentication Errors
- **700-799**: Two-Factor Authentication Errors
- **800-899**: Session Management Errors
- **900-999**: Authorization Errors
- **1000-1099**: Input Validation Errors
- **1100-1199**: Rate Limiting Errors
- **1200-1299**: Server Errors
- **1300-1399**: OAuth Errors

**Note:** This page is automatically synchronized with the error definitions in the codebase. Adding new errors only requires updating `lib/utils/errors.js` and the category code array.

**Usage:**
```
GET /mbkauthe/ErrorCode
```

---

#### `GET /icon.svg`

Serves the application's SVG icon file.

**Response:** SVG image file (Content-Type: image/svg+xml)

**Cache:** Cached for 1 year (max-age=31536000)

**Usage:**
```html
<img src="/icon.svg" alt="App Icon">
```

---

#### `GET /favicon.ico`

Serves the application's favicon.

**Aliases:** `/icon.ico`

**Response:** ICO image file (Content-Type: image/x-icon)

**Cache:** Cached for 1 year (max-age=31536000)

**Usage:**
```html
<link rel="icon" type="image/x-icon" href="/favicon.ico">
```

---

#### `GET /mbkauthe/bg.webp`

Serves the background image for authentication pages.

**Response:** WEBP image file (Content-Type: image/webp)

**Cache:** Cached for 1 year (max-age=31536000)

**Usage:**
```css
background-image: url('/mbkauthe/bg.webp');
```

---

#### `GET /mbkauthe/test`

Test endpoint to verify authentication and display user session information.

**Authentication:** Session required

**Rate Limit:** 8 requests per minute

**Response:** HTML page displaying:
- Current username
- User role
- Logout button
- Quick links to info and login pages

**Example Response:**
```html
<head> 
  <script src="/mbkauthe/main.js"></script> 
</head>
<p>if you are seeing this page than User is logged in.</p>
<p>id: '${req.session.user.id}', UserName: '${req.session.user.username}', Role: '${req.session.user.role}', SessionId: '${req.session.user.sessionId}'</p>
<button onclick="logout()">Logout</button><br>
<a href="/mbkauthe/info">Info Page</a><br>
<a href="/mbkauthe/login">Login Page</a><br>
```

**Usage:**
```
GET /mbkauthe/test
```

**Note:** This endpoint is primarily for testing and debugging authentication. It should not be used in production environments.

---

### OAuth Endpoints

#### `GET /mbkauthe/api/github/login`

Initiates the GitHub OAuth authentication flow.

**Rate Limit:** 10 requests per 5 minutes

**Query Parameters:**
- `redirect` (optional) - Relative URL to redirect after successful authentication (must start with `/` to prevent open redirect attacks)

**Response:** Redirects to GitHub OAuth authorization page

**Prerequisites:**
- `GITHUB_LOGIN_ENABLED=true` in environment
- Valid `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` configured
- User's GitHub account must be linked to an MBKAuth account in `user_github` table

**Example:**
```
GET /mbkauthe/api/github/login?redirect=/dashboard
```

**Workflow:**
1. User clicks "Login with GitHub"
2. Redirects to GitHub for authorization
3. GitHub redirects back to callback URL
4. System verifies GitHub account is linked
5. If 2FA enabled, prompts for 2FA
6. Creates session and redirects to specified URL

---

#### `GET /mbkauthe/api/github/login/callback`

Handles the OAuth callback from GitHub after user authorization.

**Rate Limit:** Inherited from OAuth rate limiter (10 requests per 5 minutes)

**Query Parameters:**
- `code` - Authorization code from GitHub (automatically provided)
- `state` - State parameter for CSRF protection (automatically provided)

**Response:** 
- Redirects to 2FA page if 2FA is enabled for the user
- Redirects to `loginRedirectURL` or stored redirect URL if 2FA is not required
- Renders error page if authentication fails

**Error Handling:**
- **GitHub Not Linked**: Returns error if GitHub account is not in `user_github` table
- **Account Inactive**: Returns error if user account is deactivated
- **Not Authorized**: Returns error if user is not allowed to access the application
- **GitHub Auth Error**: Returns error for any OAuth-related failures

**Success Flow:**
```
GitHub → /api/github/login/callback 
  → (If 2FA enabled) → /mbkauthe/2fa 
  → (If no 2FA) → loginRedirectURL or stored redirect
```

**Database Query:**
```sql
SELECT ug.*, u."UserName", u."Role", u."Active", u."AllowedApps", u."id" 
FROM user_github ug 
JOIN "Users" u ON ug.user_name = u."UserName" 
WHERE ug.github_id = $1
```

**Note:** This endpoint is automatically called by GitHub and should not be accessed directly by users.

---

## Middleware Reference

### `validateSession`

Validates that the user has an active session.

**Usage:**
```javascript
import { validateSession } from 'mbkauthe';

app.get('/protected', validateSession, (req, res) => {
  // User is authenticated
  const user = req.session.user;
  // user contains: { id, username, UserName, role, Role, sessionId }
  res.send(`Welcome ${user.username}!`);
});
```

**Behavior:**
- Checks for active session in `req.session.user`
- Attempts to restore session from `sessionId` cookie if session not found
- Validates session against database
- Checks if user account is still active
- Verifies user is authorized for the current application
- Redirects to login page if validation fails

**Session Object:**
```javascript
req.session.user = {
  id: 1,                    // User ID
  username: "john.doe",     // Username
  UserName: "john.doe",     // Username (alias)
  role: "NormalUser",       // User role
  Role: "NormalUser",       // User role (alias)
  sessionId: "abc123...",   // 64-char hex session ID
}
```

---

### `checkRolePermission(requiredRole, notAllowed)`

Checks if the authenticated user has the required role.

**Parameters:**
- `requiredRole` (string) - Required role: `"SuperAdmin"`, `"NormalUser"`, `"Guest"`, or `"Any"`/`"any"`
- `notAllowed` (string, optional) - Role that is explicitly not allowed

**Usage:**
```javascript
import { validateSession, checkRolePermission } from 'mbkauthe';

// Only SuperAdmin can access
app.get('/admin', validateSession, checkRolePermission('SuperAdmin'), (req, res) => {
  res.send('Admin panel');
});

// Any authenticated user except Guest
app.get('/content', validateSession, checkRolePermission('Any', 'Guest'), (req, res) => {
  res.send('Protected content');
});
```

**Behavior:**
- Checks if user is authenticated first
- Fetches user role from database
- Returns 403 if user has `notAllowed` role
- Returns 403 if user doesn't have `requiredRole` (unless role is "Any")
- Calls `next()` if authorized

---

### `validateSessionAndRole(requiredRole, notAllowed)`

Combined middleware for session validation and role checking.

**Parameters:**
- `requiredRole` (string) - Required role
- `notAllowed` (string, optional) - Role that is explicitly not allowed

**Usage:**
```javascript
import { validateSessionAndRole } from 'mbkauthe';

// Validate session AND check role in one middleware
app.get('/moderator', validateSessionAndRole('SuperAdmin'), (req, res) => {
  res.send('Moderator panel');
});
```

**Equivalent to:**
```javascript
app.get('/moderator', validateSession, checkRolePermission('SuperAdmin'), (req, res) => {
  res.send('Moderator panel');
});
```

---

### `authenticate(token)`

API authentication middleware for server-to-server communication.

**Parameters:**
- `token` (string) - Secret token for authentication

**Usage:**
```javascript
import { authenticate } from 'mbkauthe';

app.post('/api/data', authenticate(process.env.API_TOKEN), (req, res) => {
  res.json({ data: 'Protected API data' });
});
```

**Headers Required:**
```
Authorization: your-secret-token
```

**Behavior:**
- Checks `Authorization` header
- Compares with provided token
- Returns 401 if token doesn't match

---

### `authapi(requiredRole)`

Advanced API authentication with role-based access control.

**Parameters:**
- `requiredRole` (array, optional) - Array of allowed roles

**Usage:**
```javascript
import { authapi } from 'mbkauthe';

// Any authenticated API user
app.get('/api/data', authapi(), (req, res) => {
  console.log(req.user); // { username, UserName, role, Role }
  res.json({ data: 'API data' });
});

// Only SuperAdmin via API
app.post('/api/admin/action', authapi(['SuperAdmin']), (req, res) => {
  res.json({ success: true });
});
```

**Headers Required:**
```
Authorization: user-api-key-64-char-hex
```

**Behavior:**
- Validates API key from `Authorization` header
- Looks up user associated with API key
- Checks if user account is active
- Verifies user role if `requiredRole` is specified
- Blocks demo users from accessing endpoints
- Populates `req.user` with user information
- Returns 401 if unauthorized, 403 if insufficient permissions

**req.user Object:**
```javascript
req.user = {
  username: "john.doe",
  UserName: "john.doe",
  role: "NormalUser",
  Role: "NormalUser"
}
```

**Database Requirement:**
Requires `UserAuthApiKey` table:
```sql
CREATE TABLE "UserAuthApiKey" (
    username VARCHAR(50) PRIMARY KEY REFERENCES "Users"("UserName"),
    "key" VARCHAR(64) UNIQUE NOT NULL
);
```

---

## Error Codes

### HTTP Status Codes

| Code | Meaning | Usage |
|------|---------|-------|
| 200 | OK | Successful request |
| 400 | Bad Request | Invalid input data |
| 401 | Unauthorized | Authentication required or failed |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server-side error |

---

## Code Examples

### Basic Integration

```javascript
import express from 'express';
import mbkauthe, { validateSession } from 'mbkauthe';
import dotenv from 'dotenv';

dotenv.config();

// Configure MBKAuthe
process.env.mbkautheVar = JSON.stringify({
  APP_NAME: process.env.APP_NAME,
  SESSION_SECRET_KEY: process.env.SESSION_SECRET_KEY,
  IS_DEPLOYED: process.env.IS_DEPLOYED,
  DOMAIN: process.env.DOMAIN,
  LOGIN_DB: process.env.LOGIN_DB,
  MBKAUTH_TWO_FA_ENABLE: process.env.MBKAUTH_TWO_FA_ENABLE,
  COOKIE_EXPIRE_TIME: process.env.COOKIE_EXPIRE_TIME || 2,
  loginRedirectURL: '/dashboard'
});

const app = express();

// Mount MBKAuthe routes
app.use(mbkauthe);

// Protected route
app.get('/dashboard', validateSession, (req, res) => {
  res.send(`Welcome ${req.session.user.username}!`);
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
```

---

### Role-Based Access Control

```javascript
import { validateSession, checkRolePermission, validateSessionAndRole } from 'mbkauthe';

// Method 1: Separate middleware
app.get('/admin', 
  validateSession, 
  checkRolePermission('SuperAdmin'), 
  (req, res) => {
    res.send('Admin panel');
  }
);

// Method 2: Combined middleware
app.get('/admin', 
  validateSessionAndRole('SuperAdmin'), 
  (req, res) => {
    res.send('Admin panel');
  }
);

// Allow any role except Guest
app.get('/content', 
  validateSession,
  checkRolePermission('Any', 'Guest'),
  (req, res) => {
    res.send('Content for registered users');
  }
);

// Multiple roles (using separate middleware)
app.get('/moderator',
  validateSession,
  (req, res, next) => {
    if (['SuperAdmin', 'NormalUser'].includes(req.session.user.role)) {
      next();
    } else {
      res.status(403).send('Access denied');
    }
  },
  (req, res) => {
    res.send('Moderator panel');
  }
);
```

---

### API Authentication

```javascript
import { authenticate, authapi } from 'mbkauthe';

// Simple token authentication
app.post('/api/webhook', 
  authenticate(process.env.WEBHOOK_SECRET), 
  (req, res) => {
    // Process webhook
    res.json({ received: true });
  }
);

// API key with user validation
app.get('/api/user/profile', authapi(), async (req, res) => {
  const { username } = req.user;
  
  // Fetch user profile
  const profile = await getUserProfile(username);
  
  res.json({ success: true, profile });
});

// API key with role requirement
app.delete('/api/admin/users/:id', 
  authapi(['SuperAdmin']), 
  async (req, res) => {
    await deleteUser(req.params.id);
    res.json({ success: true });
  }
);
```

---

### Client-Side Login

```javascript
// Login form submission
document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  
  try {
    const response = await fetch('/mbkauthe/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password })
    });
    
    const data = await response.json();
    
    if (data.success) {
      if (data.twoFactorRequired) {
        // Redirect to 2FA page
        window.location.href = '/mbkauthe/2fa';
      } else {
        // Login successful, redirect
        window.location.href = data.redirectUrl || '/dashboard';
      }
    } else {
      alert(data.message || 'Login failed');
    }
  } catch (error) {
    console.error('Login error:', error);
    alert('An error occurred during login');
  }
});
```

---

### Client-Side Logout

```javascript
async function logout() {
  // Get CSRF token from page
  const csrfToken = document.querySelector('[name="_csrf"]').value;
  
  try {
    const response = await fetch('/mbkauthe/api/logout', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ _csrf: csrfToken })
    });
    
    const data = await response.json();
    
    if (data.success) {
      window.location.href = '/mbkauthe/login';
    } else {
      alert('Logout failed: ' + data.message);
    }
  } catch (error) {
    console.error('Logout error:', error);
  }
}
```

---

### Database Access

```javascript
import { dblogin } from 'mbkauthe';

// Custom query using the database pool
app.get('/api/users', validateSession, checkRolePermission('SuperAdmin'), async (req, res) => {
  try {
    const result = await dblogin.query(
      'SELECT id, "UserName", "Role", "Active" FROM "Users" ORDER BY id'
    );
    
    res.json({ 
      success: true, 
      users: result.rows 
    });
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal Server Error' 
    });
  }
});
```

---

### Error Handling

```javascript
// Custom error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ 
      success: false, 
      message: 'Invalid CSRF token' 
    });
  }
  
  res.status(500).json({ 
    success: false, 
    message: 'Internal Server Error' 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('Error/dError.handlebars', {
    layout: false,
    code: 404,
    error: 'Not Found',
    message: 'The requested page was not found.',
    pagename: 'Home',
    page: '/',
  });
});
```

---

## Security Best Practices

1. **Always use HTTPS in production** - Set `IS_DEPLOYED=true` and ensure your server uses SSL/TLS
2. **Keep SESSION_SECRET_KEY secure** - Use a strong, randomly generated key
3. **Enable 2FA for sensitive applications** - Set `MBKAUTH_TWO_FA_ENABLE=true`
4. **Validate all user input** - Never trust client-side data
5. **Use rate limiting** - Already implemented for authentication endpoints
6. **Keep dependencies updated** - Regularly update npm packages
7. **Monitor for security vulnerabilities** - Use `npm audit`
8. **Use prepared statements** - Prevent SQL injection (already implemented)
9. **Implement proper logging** - Track authentication events
10. **Regular security audits** - Review code and configurations

---

## Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/mbkauthe/api/login` | 8 requests | 1 minute |
| `/mbkauthe/api/logout` | 10 requests | 1 minute |
| `/mbkauthe/api/verify-2fa` | 5 requests | 1 minute |
| `/mbkauthe/api/github/login` | 10 requests | 5 minutes |
| `/mbkauthe/api/github/login/callback` | 10 requests | 5 minutes |
| `/mbkauthe/login` | 8 requests | 1 minute |
| `/mbkauthe/info` | 8 requests | 1 minute |
| `/mbkauthe/test` | 8 requests | 1 minute |

Rate limits are applied per IP address. Logged-in users are exempt from some rate limits (e.g., login page rate limit).

---

## Support

For issues, questions, or contributions:

- **GitHub Issues:** [https://github.com/MIbnEKhalid/mbkauthe/issues](https://github.com/MIbnEKhalid/mbkauthe/issues)
- **Email:** support@mbktech.org
- **Documentation:** [https://github.com/MIbnEKhalid/mbkauthe](https://github.com/MIbnEKhalid/mbkauthe)

---

**Last Updated:** November 17, 2025  
**Version:** 1.4.2

[← Back to README](../README.md)
