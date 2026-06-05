# Endpoints

[Back to API index](../api.md) | [Back to docs index](../../README.md) | [Back to project README](../../../README.md)

## API Endpoints

### Public Endpoints

#### `GET /login`

Redirect route that forwards to the main login page.

**Rate Limit:** No rate limiting applied

**Query Parameters:**
- All query parameters are preserved and forwarded

**Response:** 302 redirect to `/mbkauthe/login`

**Example:**
```
GET /login?redirect=/dashboard
→ Redirects to: /mbkauthe/login?redirect=/dashboard
```

---

#### `GET /signin`

Alias redirect route that forwards to the main login page.

**Rate Limit:** No rate limiting applied

**Query Parameters:**
- All query parameters are preserved and forwarded

**Response:** 302 redirect to `/mbkauthe/login`

**Example:**
```
GET /signin
→ Redirects to: /mbkauthe/login
```

---

#### `GET /mbkauthe/login`

Renders the main login page.

**Rate Limit:** 8 requests per minute (exempt for logged-in users)

**CSRF Protection:** Required (token included in form)

**Query Parameters:**
- `redirect` (optional) - URL to redirect after successful login

**Response:** HTML page with login form

**Template Variables:**
- `githubLoginEnabled` - Whether GitHub App login is enabled
- `googleLoginEnabled` - Whether Google OAuth is enabled
- `customURL` - Redirect URL after login
- `userLoggedIn` - Whether user is already authenticated
- `username` - Current username if logged in
- `version` - MBKAuthe version
- `appName` - Application name
- `csrfToken` - CSRF protection token
- `lastLoginMethod` - (optional) last login method recorded by the server (e.g., `"password"`, `"github"`, `"google"`) used to render UI badges
- `lastLoginPassword`, `lastLoginGithub`, `lastLoginGoogle` - convenience booleans derived from `lastLoginMethod` for server-side template rendering of "Last used" badges

**Example:**
```
GET /mbkauthe/login?redirect=/dashboard
```

---

#### `GET /mbkauthe/2fa`

Renders the 2FA challenge page after a login that requires TOTP.

**Rate Limit:** 5 requests per minute

---

#### `GET /mbkauthe/accounts`

Renders the account-switch page for remembered sessions on the device.

**Rate Limit:** 8 requests per minute

---

#### `GET /mbkauthe/test`

Renders a test page for the current session context.

**Rate Limit:** 8 requests per minute

---

#### `POST /mbkauthe/test`

Lightweight check to verify an authenticated session.

**Response:** `{ "success": true, "message": "You are logged in" }`

---

## Diagnostics (Dev Only)

These endpoints are only mounted when `process.env.env === "dev"`.

#### `GET /mbkauthe/db`

Renders the DB Query Monitor page. The UI fetches data from `/mbkauthe/db.json`.

**Query Parameters:**
- `limit` (optional) - number of most recent queries to show (default: 50)
- `resetDone` (optional) - UI notification flag used after reset

---

#### `GET /mbkauthe/db.json`

Returns recent DB query diagnostics.

**Query Parameters:**
- `limit` (optional) - number of most recent queries to return (default: 50)
- `reset` (optional) - set to `1` to clear the query log and counter

**Response Body:**
```json
{
  "queryCount": 120,
  "queryLimit": 50,
  "resetDone": false,
  "queryLog": [
    {
      "time": "2026-03-19T12:00:00.000Z",
      "name": "login-get-user",
      "query": "SELECT ...",
      "values": ["user"],
      "durationMs": 3.42,
      "success": true,
      "error": null,
      "request": {
        "method": "GET",
        "url": "/mbkauthe/login",
        "ip": "::1",
        "userId": 1,
        "username": "support"
      },
      "pool": {
        "total": 2,
        "idle": 1,
        "waiting": 0
      },
      "callsite": {
        "function": "validateSession",
        "file": "lib/middleware/auth.js",
        "line": 197,
        "column": 30
      }
    }
  ]
}
```

---

#### `POST /mbkauthe/db/reset`

Resets the DB query log and counters (dev-only).

**Authentication / Access:** Dev-only (mounted when `process.env.env === 'dev'` and `dbLogs=true`).

**Request Body:** None required.

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Query log and count have been reset."
}
```

**Behavior:** Clears the in-memory or persisted DB query counters and logs used by the diagnostic UI. Returns `403` when DB logs are disabled.

---

#### `GET /mbkauthe/validate-superadmin`

Validates that the current session has `SuperAdmin` role and returns a JSON summary.

---

## Additional Endpoints

The endpoints below are active in the router but are not fully expanded above. Use this list as a reference.

**Auth & Session:**

- `POST /mbkauthe/api/verify-2fa` - Verifies TOTP and completes login.
- `POST /mbkauthe/api/logout` - Logs out the current session.
- `GET /mbkauthe/api/account-sessions` - Lists remembered accounts for the current device.
- `POST /mbkauthe/api/switch-session` - Switches active session to another remembered account.
- `POST /mbkauthe/api/logout-all` - Logs out all remembered accounts on the device.

**Session Validation:**

- `GET /mbkauthe/api/checkSession` - Checks session validity (cookie-based).
- `POST /mbkauthe/api/checkSession` - Checks session validity by sessionId (body).
- `POST /mbkauthe/api/verifySession` - Returns session details by sessionId (body).

**OAuth:**

- `GET /mbkauthe/api/github/login` - Starts GitHub App login flow.
- `GET /mbkauthe/api/github/login/callback` - GitHub App callback.
- `GET /mbkauthe/api/google/login` - Starts Google OAuth login flow.
- `GET /mbkauthe/api/google/login/callback` - Google OAuth callback.

**Info & UI:**

- `GET /mbkauthe/info` and `GET /mbkauthe/i` - Info page.
- `GET /mbkauthe/info.json` and `GET /mbkauthe/i.json` - Info page JSON.
- `GET /mbkauthe/ErrorCode` - Error codes page.
- `GET /mbkauthe/user/profilepic` - User profile picture proxy.
 - `GET /mbkauthe/` - Mount root; renders the test/home page (alias of `/mbkauthe/test`).

**Admin:**

- `POST /mbkauthe/api/terminateAllSessions` - Terminates all sessions (requires `Main_SECRET_TOKEN`).

**Static Assets:**

- `GET /mbkauthe/main.js`
- `GET /mbkauthe/main.css`
- `GET /mbkauthe/bg.webp`

Also served at the root level (outside `/mbkauthe`) are site icons:

- `GET /icon.svg` - Main application SVG icon (root-level)
- `GET /favicon.ico` - Fallback favicon (root-level)
- `GET /icon.png` - Additional icon size (root-level)

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

Note: the server also sets an encrypted `sessionId` cookie for browser sessions; treat the cookie as an opaque value and avoid parsing it client-side.

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

#### `GET /mbkauthe/api/checkSession`

Checks whether the current session (cookie-based) is valid. Returns a JSON response suitable for AJAX/SPA checks.

**Authentication:** Requires a valid session cookie set by `/mbkauthe/api/login`.

**Success Response (200 OK):**
```json
{
  "sessionValid": true,
  "expiry": "2025-12-27T12:34:56.000Z"
}
```

**Error Responses (examples):**
- 200 Session invalid ( { "sessionValid": false, "expiry": null } )
- 500 Internal Server Error (rare)

**Example Request:**
```javascript
fetch('/mbkauthe/api/checkSession')
  .then(res => res.json())
  .then(data => {
    if (data.sessionValid) {
      // session active, expiry available in data.expiry
    } else {
      // not authenticated
    }
  });
```

---

#### `POST /mbkauthe/api/checkSession` (body)

Validate a session by providing a session identifier in the request body. Useful for server-to-server checks or when you have an encrypted `sessionId` value from a cookie and need to validate it server-side.

**Rate Limit:** 8 requests per minute (same limiter used by public session endpoints)

**Request Body (JSON):**
```json
{
  "sessionId": "string (uuid or encrypted string)",
  "isEncrypt": "boolean | 'true' (optional, indicates sessionId is encrypted)
}
```

**Notes:**
- The endpoint accepts `isEncrypt` or the misspelled `isEncryt` (both `true` or the string `'true'` are accepted).
- If `isEncrypt` is true, the server will first attempt `decodeURIComponent()` on the value and then decrypt it (AES) to obtain a UUID session id. If decryption fails or the resulting value is not a UUID, the server returns `400 Bad Request` with `SESSION_INVALID`.
- A missing `sessionId` returns `400 Bad Request` with `MISSING_REQUIRED_FIELD`.

**Success Response (200 OK):**
```json
{
  "sessionValid": true,
  "expiry": "2025-12-27T12:34:56.000Z"
}
```

**Invalid/Expired Session:**
- Returns 200 with `{ "sessionValid": false, "expiry": null }` for unknown/expired/inactive sessions.

**Example Request (Fetch):**
```javascript
fetch('/mbkauthe/api/checkSession', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ sessionId: '550e8400-e29b-41d4-a716-446655440000' })
}).then(r => r.json()).then(console.log);
```

**Example Request (Encrypted sessionId):**
```javascript
fetch('/mbkauthe/api/checkSession', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ sessionId: 'ENCRYPTED_VALUE', isEncrypt: true })
}).then(r => r.json()).then(console.log);
```

---

#### `POST /mbkauthe/api/verifySession`

Returns session details for a provided `sessionId`. Intended for server-side validation and to retrieve associated user metadata without relying on an active cookie session.

**Request Body (JSON):**
```json
{
  "sessionId": "string (uuid or encrypted string)",
  "isEncrypt": "boolean | 'true' (optional)"
}
```

**Behavior and Notes:**
- `isEncrypt`/`isEncryt` have the same behavior as in `/api/checkSession`.
- If the session is valid and active, the response includes `username` and `role`.
- Missing or invalid `sessionId` results in `400 Bad Request` with an appropriate error code (`MISSING_REQUIRED_FIELD` or `SESSION_INVALID`).

**Success Response (200 OK):**
```json
{
  "valid": true,
  "expiry": "2025-12-27T12:34:56.000Z",
  "username": "john.doe",
  "role": "NormalUser"
}
```

**Invalid/Expired Session:**
- Returns 200 with `{ "valid": false, "expiry": null }` for unknown/expired/inactive sessions.

**Example Request:**
```javascript
fetch('/mbkauthe/api/verifySession', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ sessionId: '550e8400-e29b-41d4-a716-446655440000' })
}).then(r => r.json()).then(console.log);
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

Note: the server also sets an encrypted `sessionId` cookie for browser sessions; treat the cookie as an opaque value and avoid parsing it client-side.

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

### Multi-Account Endpoints

#### `GET /mbkauthe/accounts`

Renders the account switching page, allowing users to switch between remembered accounts on the device.

**Rate Limit:** 8 requests per minute

**CSRF Protection:** Required

**Response:** HTML page with account list

**Template Variables:**
- `customURL` - Redirect URL after switch
- `userLoggedIn` - Whether a user is currently logged in
- `username` - Current username
- `fullname` - Current user's full name
- `role` - Current user's role

**Usage:**
```
GET /mbkauthe/accounts
```

---

#### `GET /mbkauthe/api/account-sessions`

Retrieves the list of remembered accounts for the current device.

**Rate Limit:** 8 requests per minute

**Response (200 OK):**
```json
{
  "accounts": [
    {
      "sessionId": "64-char-session-id",
      "username": "john.doe",
      "fullName": "John Doe",
      "isCurrent": true
    },
    {
      "sessionId": "another-session-id",
      "username": "jane.smith",
      "fullName": "Jane Smith",
      "isCurrent": false
    }
  ],
  "currentSessionId": "64-char-session-id"
}
```

**Behavior:**
- Validates each stored session against the database
- Automatically removes invalid/expired sessions from the cookie
- Returns only valid, active sessions

---

#### `POST /mbkauthe/api/switch-session`

Switches the active session to another remembered account.

**Rate Limit:** 8 requests per minute

**Request Body:**
```json
{
  "sessionId": "target-session-id (required)",
  "redirect": "/dashboard (optional)"
}
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "username": "jane.smith",
  "fullName": "Jane Smith",
  "redirect": "/dashboard"
}
```

**Error Responses:**

| Status Code | Message |
|------------|---------|
| 400 | Invalid session ID format |
| 401 | Session expired |
| 403 | Account not available on this device |
| 500 | Internal Server Error |

**Behavior:**
- Verifies the target session exists in the device's remembered list
- Validates the session against the database
- Regenerates the session ID to prevent fixation
- Updates session cookies and current user context

---

#### `POST /mbkauthe/api/logout-all`

Logs out all remembered accounts on the current device.

**Rate Limit:** 8 requests per minute

**Response (200 OK):**
```json
{
  "success": true,
  "message": "All accounts logged out"
}
```

**Behavior:**
- Deletes all session records associated with the device's remembered accounts from the database
- Clears the account list cookie
- Destroys the current session
- Clears all session cookies

---

#### `POST /mbkauthe/api/terminateAllSessions`

Terminates all active sessions across all users (admin only).

**Authentication:** API token required (via `authenticate` middleware)

**Rate Limit:** 3 requests per 5 minutes

**Headers:**
```
Authorization: your-main-secret-token
```

**Request Body:** None required

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

**Implementation Details:**
- Clears all user session IDs in the database (`Users` table) where sessions exist
- Deletes all active session records from the `session` table  
- Destroys the current request session
- Clears session cookies
- Runs database operations in parallel for better performance
- Uses optimized queries with WHERE clauses to avoid unnecessary updates

**Example Request:**
```javascript
fetch('/mbkauthe/api/terminateAllSessions', {
  method: 'POST',
  headers: {
    'Authorization': process.env.MAIN_SECRET_TOKEN,
    'Content-Type': 'application/json'
  }
})
.then(response => response.json())
.then(data => {
  if (data.success) {
    console.log('All sessions terminated successfully');
  }
});
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

**Rate Limit:** No rate limiting applied

**Cache:** Cached for 1 year (max-age=31536000)

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

#### `GET /icon.svg`

Serves the application's SVG icon file from the root level.

**Rate Limit:** No rate limiting applied

**Response:** SVG image file (Content-Type: image/svg+xml)

**Cache:** Cached for 1 year (max-age=31536000)

**Note:** This route is mounted at the root level (not under `/mbkauthe`)

**Also served:** `/favicon.ico` and `/icon.png` are provided as additional icon fallbacks at the same root level.

**Usage:**
```html
<img src="/icon.svg" alt="App Icon">
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

#### `GET /mbkauthe/user/profilepic`

Serves the current user's profile picture or a default icon.

**Authentication:** Optional (returns default icon if not logged in)

**Response:** 
- If logged in with valid profile picture URL: 302 redirect to the user's profile picture URL (from `Users.Image` column)
- If not logged in or no profile picture: SVG image file (Content-Type: image/svg+xml) streaming `/icon.svg`

**Cache:** 
- Profile picture URL is cached in session for performance
- Cache is automatically cleared on login, logout, or account switch

**Behavior:**
1. First request: Queries `Users` table for `Image` column value
2. Subsequent requests: Returns cached value from session
3. On login/logout/switch: Cache is invalidated and fresh data is fetched

**Usage:**
```html
<img src="/mbkauthe/user/profilepic" alt="Profile Picture">
```

**Example Response Flow:**
```
User logged in → Query DB → Cache URL → Redirect to URL
User not logged in → Stream /icon.svg
Empty Image value → Stream /icon.svg
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

#### GitHub App

##### `GET /mbkauthe/api/github/login`

Initiates the GitHub App authentication flow.

**Rate Limit:** 10 requests per 5 minutes

**CSRF Protection:** Required (state parameter used for validation)

**Query Parameters:**
- `redirect` (optional) - Relative URL to redirect after successful authentication (must start with `/` to prevent open redirect attacks)

**Response:** Redirects to GitHub authorization page

**Prerequisites:**
- `GITHUB_LOGIN_ENABLED=true` in environment
- Valid `GITHUB_APP_CLIENT_ID` and `GITHUB_APP_CLIENT_SECRET` configured
- User's GitHub account must be linked to an MBKAuth account in `user_github` table

**Example:**
```
GET /mbkauthe/api/github/login?redirect=/dashboard
```

**Workflow:**
1. User clicks "Login with GitHub"
2. CSRF token generated and stored in session
3. Redirects to GitHub authorization page
4. GitHub redirects back to callback URL with authorization `code`
5. System verifies `github_id` is linked
6. If 2FA enabled, prompts for 2FA
7. Creates session and redirects to specified URL

---

##### `GET /mbkauthe/api/github/login/callback`

Handles the callback from GitHub after user authorization.

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
- **GitHub Auth Error**: Returns error for provider authentication failures

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

#### Google OAuth

##### `GET /mbkauthe/api/google/login`

Initiates the Google OAuth 2.0 authentication flow.

**Rate Limit:** 10 requests per 5 minutes

**CSRF Protection:** Required (state parameter used for validation)

**Query Parameters:**
- `redirect` (optional) - Relative URL to redirect after successful authentication (must start with `/` to prevent open redirect attacks)

**Response:** Redirects to Google OAuth authorization page

**Prerequisites:**
- `GOOGLE_LOGIN_ENABLED=true` in environment
- Valid `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` configured
- User's Google account must be linked to an MBKAuth account in `user_google` table

**Example:**
```
GET /mbkauthe/api/google/login?redirect=/dashboard
```

**Workflow:**
1. User clicks "Login with Google"
2. CSRF token generated and stored in session
3. Redirects to Google for authorization
4. Google redirects back to callback URL
5. System verifies Google account is linked
6. If 2FA enabled, prompts for 2FA
7. Creates session and redirects to specified URL

**Error Responses:**
- **Configuration Error**: Returns 500 if Google OAuth credentials are not properly configured
- **Disabled**: Returns 403 if `GOOGLE_LOGIN_ENABLED` is false

---

##### `GET /mbkauthe/api/google/login/callback`

Handles the OAuth callback from Google after user authorization.

**Rate Limit:** Inherited from OAuth rate limiter (10 requests per 5 minutes)

**Query Parameters:**
- `code` - Authorization code from Google (automatically provided)
- `state` - State parameter for CSRF protection (automatically provided)

**Response:** 
- Redirects to 2FA page if 2FA is enabled for the user
- Redirects to `loginRedirectURL` or stored redirect URL if 2FA is not required
- Renders error page if authentication fails

**Error Handling:**
- **Google Not Linked**: Returns error if Google account is not in `user_google` table
- **Account Inactive**: Returns error if user account is deactivated
- **Not Authorized**: Returns error if user is not allowed to access the application
- **Google Auth Error**: Returns error for any OAuth-related failures
- **Token Error**: Handles expired or invalid OAuth tokens with user-friendly message
- **CSRF Validation Failed**: Returns 403 if state parameter doesn't match

**Success Flow:**
```
Google → /api/google/login/callback 
  → (CSRF Validation)
  → (If 2FA enabled) → /mbkauthe/2fa 
  → (If no 2FA) → loginRedirectURL or stored redirect
```

**Database Query:**
```sql
SELECT ug.*, u."UserName", u."Role", u."Active", u."AllowedApps", u."id" 
FROM user_google ug 
JOIN "Users" u ON ug.user_name = u."UserName" 
WHERE ug.google_id = $1
```

**Note:** This endpoint is automatically called by Google and should not be accessed directly by users.

---

#### OAuth Security Features

Both GitHub and Google OAuth implementations include:

- **CSRF Protection**: State parameter validation to prevent cross-site request forgery
- **Session Security**: OAuth state tokens stored in session and validated on callback
- **Rate Limiting**: 10 requests per 5 minutes to prevent abuse
- **Token Validation**: Proper handling of expired or invalid OAuth tokens
- **Redirect Validation**: Only allows relative URLs to prevent open redirect attacks
- **Account Linking**: Users must pre-link OAuth accounts before login
- **2FA Integration**: Respects 2FA settings and trusted device configuration
- **Comprehensive Error Handling**: User-friendly error messages for all failure scenarios

---

