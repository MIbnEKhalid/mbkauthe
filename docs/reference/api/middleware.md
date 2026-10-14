# Express Middleware Reference

MBKAuthe v6 provides a modular suite of Express middleware functions for authentication, role validation, granular permissions, security headers, CORS, and request context.

---

## 1. Authentication Middleware

### `validateSession` (alias: `sessVal`)
Verifies that the incoming request has a valid, active session or Bearer API token. Populates `req.session.user` and `(req as any).auth` (`AuthContext`).

```typescript
import { sessVal } from "mbkauthe";

app.get("/dashboard", sessVal, (req, res) => {
  res.send(`Logged in as ${req.session.user.username}`);
});
```

### `authenticate(secretOrValidator)`
Protects routes using a fixed shared secret token or custom validator:

```typescript
import { authenticate } from "mbkauthe";

// Require Bearer token matching MAIN_SECRET_TOKEN
app.post("/internal/sync", authenticate(process.env.MAIN_SECRET_TOKEN), handler);
```

### `validateApiSession`
Validates requests authenticating via `Authorization: Bearer <mbk_pat_...>` tokens.

### `strictValidateSession` (alias: `strictSessVal`)
Strict session validation that requires continuous verification against the database without in-memory cookie shortcuts.

### `reloadSessionUser`
Forces a fresh reload of user details, active roles, and permissions directly from the database into `req.session.user`.

```typescript
import { sessVal, reloadSessionUser } from "mbkauthe";

app.get("/account", sessVal, reloadSessionUser, (req, res) => {
  res.json({ user: req.session.user });
});
```

---

## 2. Authorization & Role Middleware

### `checkRolePermission(roles, notAllowed)` (alias: `roleChk`)
Ensures the authenticated user possesses one of the specified roles.

```typescript
import { sessVal, roleChk } from "mbkauthe";

// Single role
app.get("/admin", sessVal, roleChk("admin"), handler);

// Multiple acceptable roles
app.get("/manage", sessVal, roleChk(["admin", "superadmin"]), handler);

// Blacklist role (allow all except guest)
app.post("/post", sessVal, roleChk("*", "guest"), handler);
```

### `validateSessionAndRole(roles, notAllowed)` (alias: `sessRole`)
Combines `validateSession` and `checkRolePermission` into a single middleware.

```typescript
import { sessRole } from "mbkauthe";

app.get("/admin", sessRole("superadmin"), handler);
```

### `strictValidateSessionAndRole(roles, notAllowed)` (alias: `strictSessRole`)
Combines `strictValidateSession` and role checking.

---

## 3. Numeric Bitmask Permission Middleware

### `checkPermission(permission)` (alias: `permChk`)
Checks whether the authenticated user or API token holds the required resource action bitmask. Evaluates in a single CPU cycle (< 1ns) with 0 database queries using cached session bitmasks.

Accepts:
- `ActionDescriptor` (e.g. `AppPermissions.users.delete`)
- Permission target string (e.g. `"users:delete"`, `"users.delete"`, or `"basic.access"`)
- `[resource, mask]` tuple (e.g. `["users", StandardActionBits.DELETE]`)

```typescript
import { sessVal, permChk } from "mbkauthe";
import { AppPermissions } from "./permissions.js";

// ActionDescriptor
app.delete("/users/:id", sessVal, permChk(AppPermissions.users.delete), handler);

// String shorthand
app.get("/users", sessVal, permChk("users.view"), handler);
```

### `validateSessionAndPermission(permission)` (alias: `sessPerm`)
Pipeline combining session validation and bitmask permission verification in a single middleware call.

```typescript
import { sessPerm } from "mbkauthe";
import { AppPermissions } from "./permissions.js";

app.post("/users", sessPerm(AppPermissions.users.create), handler);
```

---

## 4. Security & Infrastructure Middleware

- `securityHeadersMiddleware`: Sets strict HSTS, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy headers.
- `corsMiddleware`: Handles domain-specific CORS origin checking.
- `sessionRestorationMiddleware`: Automatically decrypts and restores `req.session` from `session_id` cookies.
- `sessionCookieSyncMiddleware`: Automatically syncs refreshed session timestamps back into client cookies.
- `requestContextMiddleware`: Injects unique request tracing IDs into async database contexts.

