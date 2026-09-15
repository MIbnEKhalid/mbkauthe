# Express Middleware Reference

MBKAuthe v6 provides a modular suite of Express middleware functions for authentication, role validation, granular permissions, security headers, CORS, and request context.

---

## 1. Authentication Middleware

### `validateSession` (alias: `sessVal`)
Verifies that the incoming request has a valid, active session or Bearer API token. Populates `req.session.user` and `req.session.permissions`.

```typescript
import { sessVal } from "mbkauthe";

app.get("/dashboard", sessVal, (req, res) => {
  res.send(`Logged in as ${req.session.user.username}`);
});
```

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
Ensures the user possesses one of the specified roles.

```typescript
import { sessVal, roleChk } from "mbkauthe";

// Single role
app.get("/admin", sessVal, roleChk("admin"), handler);

// Multiple acceptable roles
app.get("/manage", sessVal, roleChk(["admin", "superadmin"]), handler);

// Blacklist role
app.post("/post", sessVal, roleChk("*", "guest"), handler);
```

### `validateSessionAndRole(roles, notAllowed)` (alias: `sessRole`)
Combines `validateSession` and `checkRolePermission` into a single middleware.

```typescript
import { sessRole } from "mbkauthe";

app.get("/admin", sessRole("superadmin"), handler);
```

---

## 3. Dynamic Permission Middleware

### `checkPermission(permission)` (alias: `permChk`)
Checks whether the authenticated user or API token holds the required `app:service:action` permission.

```typescript
import { sessVal, permChk } from "mbkauthe";
import { CorePermissions } from "./permissions.js";

app.delete("/users/:id", sessVal, permChk(CorePermissions.users.delete), handler);
```

### `validateSessionAndPermission(permission)` (alias: `sessPerm`)
Combines session validation and permission verification.

```typescript
import { sessPerm } from "mbkauthe";
import { CorePermissions } from "./permissions.js";

app.post("/users", sessPerm(CorePermissions.users.write), handler);
```

---

## 4. Security & Infrastructure Middleware

- `securityHeadersMiddleware`: Sets strict HSTS, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy headers.
- `corsMiddleware`: Handles domain-specific CORS origin checking.
- `sessionRestorationMiddleware`: Automatically decrypts and restores `req.session` from `session_id` cookies.
- `requestContextMiddleware`: Injects unique request tracing IDs into async database contexts.
