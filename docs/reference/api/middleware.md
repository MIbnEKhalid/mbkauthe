# Middleware

[Back to API index](../api.md) | [Back to docs index](../../README.md) | [Back to project README](../../../README.md)

## Middleware Reference

### `validateSession`/`sessRole`

Validates that the user has an active session.

**Usage:**
```javascript
import { sessRole } from 'mbkauthe';

app.get('/protected', sessRole, (req, res) => {
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

**JSON vs HTML error responses:**

When `validateSession` fails, MBKAuthe will either render an HTML error/login page (browser flow) or return a JSON error response (API/AJAX flow). A request is treated as **JSON** when any of these are true:

- URL/path starts with `/mbkauthe/api/` or `/api/`
- `X-Requested-With: XMLHttpRequest`
- `Accept` indicates JSON (e.g., `application/json`) and does not explicitly prefer `text/html`
- `User-Agent` matches a non-browser client (e.g., `curl`, `wget`, `Postman`, `Insomnia`)
- `User-Agent: json` (explicitly forces JSON responses)

**Example (force JSON errors on a page route):**
```bash
curl -i -H "User-Agent: json" http://localhost:3000/mbkauthe/test
```

### reloadSessionUser(req, res)

Use this helper when you need to refresh the values stored in `req.session.user` from the authoritative database record (for example, after a profile update that changes FullName, or when session expiration policies are updated).

- Behavior:
  - Validates the session against the database (sessionId, active)
  - Updates `req.session.user` fields: `username`, `role`, `allowedApps`, `fullname`
  - Uses cached `fullName` cookie if available; falls back to querying `profiledata`
  - Syncs `username`, `fullName`, and `sessionId` cookies for client display
  - If the session is invalid (sessionId mismatch, inactive account, or unauthorized), it destroys the session and clears cookies

- Returns: `Promise<boolean>` — `true` if session was refreshed and still valid, `false` if session was invalidated or reload failed.

- Example:
```javascript
import { reloadSessionUser } from 'mbkauthe';

// After updating profile data
app.post('/mbkauthe/api/update-profile', sessRole, async (req, res) => {
  // ... update profiledata.FullName in DB ...
  const refreshed = await reloadSessionUser(req, res);
  if (!refreshed) {
    return res.status(401).json({ success: false, message: 'Session invalidated' });
  }
  res.json({ success: true, fullname: req.session.user.fullname });
});
```

**Session Object:**
```javascript
req.session.user = {
  id: 1,                    // User ID
  username: "john.doe",     // Username (login name)
  fullname: "John Doe",     // Optional display name fetched from profiledata
  role: "NormalUser",       // User role
  sessionId: "abc123...",   // 64-char hex session ID
}
```

**Session Cookie Sync:**
- The middleware sets non-httpOnly cookies for client display:
  - `username` — the login username (exposed for UI)
  - `fullName` — the display name (falls back to username if not available)

These cookies allow front-end UI to display a friendly name without making extra requests to the server.
---

### `checkRolePermission(requiredRole, notAllowed)`/`roleChk `

Checks if the authenticated user has the required role.

**Parameters:**
- `requiredRole` (string) - Required role: `"SuperAdmin"`, `"NormalUser"`, `"Guest"`, `"member"`, or `"Any"`/`"any"`
- `notAllowed` (string, optional) - Role that is explicitly not allowed

**Usage:**
```javascript
import { sessVal, roleChk } from 'mbkauthe';

// Only SuperAdmin can access
app.get('/admin', sessVal, roleChk('SuperAdmin'), (req, res) => {
  res.send('Admin panel');
});

// Any authenticated user except Guest
app.get('/content', sessVal, roleChk('Any', 'Guest'), (req, res) => {
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

### `validateSessionAndRole(requiredRole, notAllowed)`/`sessRole`

Combined middleware for session validation and role checking.

**Parameters:**
- `requiredRole` (string) - Required role
- `notAllowed` (string, optional) - Role that is explicitly not allowed

**Usage:**
```javascript
import { sessRole, roleChk } from 'mbkauthe';

// Validate session AND check role in one middleware
app.get('/moderator', sessRole('SuperAdmin'), (req, res) => {
  res.send('Moderator panel');
});
```

**Equivalent to:**
```javascript
app.get('/moderator', sessVal, roleChk('SuperAdmin'), (req, res) => {
  res.send('Moderator panel');
});
```

---

### Strict validation helpers

For endpoints that must reject API token-based authentication and only accept browser session cookies, MBKAuthe exposes two strict helpers:

- `strictValidateSession`/`strictSessVal` — same as `validateSession`, but rejects requests that provide `Authorization` headers (API tokens) and returns `401` when a token is used.
- `strictValidateSessionAndRole(requiredRole, notAllowed)`/`strictSessRole` — combined helper that behaves like `validateSessionAndRole` but enforces strict (cookie-only) authentication.

**Usage examples:**
```javascript
import { strictSessVal, strictSessRole } from 'mbkauthe';

// Accept only cookie sessions
app.get('/sensitive', strictSessVal, (req, res) => {
  res.send('Sensitive data');
});

// Validate session AND role, using cookie-only authentication
app.get('/admin', strictSessRole('SuperAdmin'), (req, res) => {
  res.send('Admin');
});
```

---

### Response Utilities

MBKAuthe exports small helpers to assist with page rendering and context:

- `getUserContext(req)` — returns a lightweight context object for templates: `{ userLoggedIn, isuserlogin, username, fullname, role, allowedApps }`.
- `renderPage(req, res, fileLocation, layout = true, data = {})` — renders a template with the user/context merged into the data; returns a Promise and yields the typical Express `res.render` behavior.
- `renderError(res, req, options)` — renders the standardized error page; note the signature is `(res, req, options)` and `options` follow the `ErrorRenderOptions` described in the types.

**Example:**

```javascript
import { getUserContext, renderPage, renderError } from 'mbkauthe';

app.get('/dashboard', (req, res) => {
  const ctx = getUserContext(req);
  return renderPage(req, res, 'info', true, { greeting: 'Hello', ...ctx });
});

app.get('/err', (req, res) => {
  return renderError(res, req, {
    layout: false,
    code: 500,
    error: "Internal Server Error",
    message: "Simulated 500 Error",
    details: "This is a simulated 500 error page for testing purposes.",
    pagename: "Home",
    page: "/mbkauthe/login",
  });
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
Authorization: Bearer your-secret-token
```

You can also send the raw token without the `Bearer` prefix.

**Behavior:**
- Checks `Authorization` header
- Extracts the token (strips optional `Bearer` prefix)
- Compares the provided token to the expected token using a timing-safe SHA-256 hash comparison
- Returns 401 if token doesn't match

---

