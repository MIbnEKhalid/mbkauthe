# Role-Based Access Control (RBAC) Guide

[Back to docs index](../README.md) | [Back to project README](../../README.md)

MBKAuthe provides built-in, granular **Role-Based Access Control (RBAC)** and **Application Scope Verification** to protect Express routes and API endpoints.

---

## 1. System Roles

MBKAuthe defines four standard system roles:

| Role | Hierarchy Level | Capabilities & Access |
| :--- | :--- | :--- |
| `superadmin` | Level 4 (Highest) | Full system administration, user management, cross-application bypass, session termination, token management. |
| `normaluser` | Level 3 (Standard) | Default registered user role. Can access authenticated user features for assigned applications in `allowed_apps`. |
| `member` | Level 2 (Restricted) | Application member with restricted write/read privileges. |
| `guest` | Level 1 (Read-only) | Temporary or unverified visitor role with strictly limited read access. |

---

## 2. Middleware Helpers

Import RBAC middleware helpers from `"mbkauthe"`:

```javascript
import { sessVal, roleChk, sessRole, strictSessRole } from "mbkauthe";
```

### `sessRole(requiredRole, notAllowed)`

Combined session validation and role enforcement. This is the recommended middleware for most protected routes.

```javascript
import express from "express";
import { sessRole } from "mbkauthe";

const router = express.Router();

// Route accessible only by superadmin
router.get("/admin/dashboard", sessRole("superadmin"), (req, res) => {
  res.render("admin-dashboard", { user: req.session.user });
});

// Route accessible by any authenticated user EXCEPT guest
router.get("/app/workspace", sessRole("Any", "guest"), (req, res) => {
  res.render("workspace", { user: req.session.user });
});
```

### `roleChk(requiredRole, notAllowed)`

Standalone role-checking middleware used after `sessVal` or custom authentication:

```javascript
import { sessVal, roleChk } from "mbkauthe";

router.post("/api/settings", sessVal, roleChk("superadmin"), (req, res) => {
  res.json({ success: true, message: "Settings saved" });
});
```

### `strictSessRole(requiredRole, notAllowed)`

Enforces strict browser session cookie authentication (rejects bearer API tokens with a `401 Unauthorized` response):

```javascript
import { strictSessRole } from "mbkauthe";

// Sensitive route that must never be callable via API tokens
router.post("/profile/delete-account", strictSessRole("normaluser"), (req, res) => {
  // delete account logic
});
```

---

## 3. Application-Level Scoping (`allowed_apps`)

In multi-application ecosystems, users have an `allowed_apps` JSONB array column in `mbkcore_users`:

```json
{
  "allowed_apps": ["portal", "analytics", "billing"]
}
```

- When `APP_NAME="portal"` is configured, `sessRole` / `sessVal` verifies that the current application name is present in `req.session.user.allowed_apps`.
- Users with `superadmin` role automatically bypass `allowed_apps` checks.
- If a user attempts to access an unauthorized application, MBKAuthe responds with error code `902 - APP_ACCESS_DENIED`.

---

## 4. Checking Roles Programmatically

Inside route handlers or service layers, inspect the session context:

```javascript
app.get("/api/reports", sessRole("normaluser"), (req, res) => {
  const { role, username } = req.session.user;

  if (role === "superadmin") {
    // Return all tenant reports
    return res.json({ allReports: true });
  }

  // Return user-specific reports
  return res.json({ userReports: true, username });
});
```

---

## 5. Security Best Practices

1. **Deny by Default**: Always protect sensitive mutation routes with `sessRole("superadmin")` or strict role checks.
2. **Do Not Trust Client Role Headers**: MBKAuthe validates user roles against the authoritative database record on active session checks.
3. **Use `reloadSessionUser(req, res)`**: When modifying roles or permissions in the database, refresh the session object immediately.
