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
  // user contains: { user_id, username, role, session_id, allowed_apps, full_name }
  res.send(`Welcome ${user.username}!`);
});
```

**Behavior:**
- Checks for active session in `req.session.user`
- Attempts to restore session from `session_id` cookie if session not found
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

Use this helper when you need to refresh the values stored in `req.session.user` from the authoritative database record (for example, after a profile update that changes full_name, or when session expiration policies are updated).

- Behavior:
  - Validates the session against the database (session_id, active)
  - Updates `req.session.user` fields: `user_id`, `username`, `role`, `allowed_apps`, `full_name`
  - Uses cached `full_name` cookie if available; falls back to querying database
  - Syncs `full_name` and `session_id` cookies
  - If the session is invalid (session_id mismatch, inactive account, or unauthorized), it destroys the session and clears cookies

- Returns: `Promise<boolean>` — `true` if session was refreshed and still valid, `false` if session was invalidated or reload failed.

- Example:
```javascript
import { reloadSessionUser } from 'mbkauthe';

// After updating profile data
app.post('/mbkauthe/api/update-profile', sessRole, async (req, res) => {
  // ... update profiledata.full_name in DB ...
  const refreshed = await reloadSessionUser(req, res);
  if (!refreshed) {
    return res.status(401).json({ success: false, message: 'Session invalidated' });
  }
  res.json({ success: true, full_name: req.session.user.full_name });
});
```

**Session Object:**
```javascript
req.session.user = {
  user_id: 1,               // User ID
  username: "john.doe",     // Username (login name)
  full_name: "John Doe",    // Optional display name fetched from profiledata
  role: "normaluser",       // User role
  session_id: "abc123...",  // 64-char hex session ID
  allowed_apps: ["portal"], // Allowed applications
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
- `requiredRole` (string) - Required role: `"superadmin"`, `"normaluser"`, `"guest"`, `"member"`, or `"Any"`/`"any"`
- `notAllowed` (string, optional) - Role that is explicitly not allowed

**Usage:**
```javascript
import { sessVal, roleChk } from 'mbkauthe';

// Only superadmin can access
app.get('/admin', sessVal, roleChk('superadmin'), (req, res) => {
  res.send('Admin panel');
});

// Any authenticated user except guest
app.get('/content', sessVal, roleChk('Any', 'guest'), (req, res) => {
  res.send('Protected content');
});
```

**Behavior:**
- Checks if user is authenticated first
- Fetches user role from database
- Returns 403 if user has `notAllowed` role
- Returns 403 if user doesn't have `requiredRole` (unless role is "Any")
- Calls `next()` if authorized

403 responses state which role is required. JSON responses include
`requiredRole` (or `notAllowedRole` when the blocked role is the reason), and
the rendered error page shows the same detail in its message.

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
app.get('/moderator', sessRole('superadmin'), (req, res) => {
  res.send('Moderator panel');
});
```

**Equivalent to:**
```javascript
app.get('/moderator', sessVal, roleChk('superadmin'), (req, res) => {
  res.send('Moderator panel');
});
```

---

### `sessPerm(requiredPermission)` and `permChk(requiredPermission)`

Dynamic, fine-grained permission middleware for the `app:service:action` model.
See the [Permissions guide](../../guides/permissions.md).

- `sessPerm(permission)` — validates the session **and** checks the permission
  (equivalent of `sessRole` but for a permission string).
- `permChk(permission)` — composable guard to chain after session validation
  (equivalent of `roleChk` but for a permission string).

**Parameters:**
- `requiredPermission` (string, optional) - A permission string such as
  `Permissions.posts.delete` (`app:service:action`; segments may be `*`).
  The `service.action` shorthand resolves to the global namespace (`basic.access`
  becomes `global:basic:access`). When omitted, global basic access is required.

**Usage:**
```javascript
import { sessPerm, permChk, sessVal } from 'mbkauthe';
import { Permissions } from './permissions.js';

// Validate session AND check permission in one middleware
app.delete('/api/posts/:id', sessPerm(Permissions.posts.delete), deletePost);

// Equivalent split form
app.delete('/api/posts/:id', sessVal, permChk(Permissions.posts.delete), deletePost);
```

**Behavior:**
- SuperAdmin always passes (system-level bypass).
- Unauthenticated requests receive HTTP 401.
- Requests without the required permission receive HTTP 403 using the existing
  JSON-vs-HTML error response behavior.
- 403 responses state which permission is required: JSON includes
  `requiredPermission` (`global:basic:access` for `basic.access`) and the
  rendered error page shows the required permission in its message.
- No database query is performed on this path — the decision uses the
  session-cached `req.session.user.permissions`.

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
app.get('/admin', strictSessRole('superadmin'), (req, res) => {
  res.send('Admin');
});
```

---

### Response Utilities

MBKAuthe exports small helpers to assist with page rendering and context:

- `getUserContext(req)` — returns a lightweight context object for templates: `{ userLoggedIn, user_id, username, full_name, role, allowed_apps }`.
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

