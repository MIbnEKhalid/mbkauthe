# Role-Based Access Control (RBAC) in MBKAuthe v6

MBKAuthe v6 provides hierarchical and multi-role Role-Based Access Control (RBAC) integrated into the session lifecycle, Express middleware routing, and the decoupled `AuthorizationService`.

---

## 1. Built-in Global Roles

MBKAuthe establishes four default roles with strict hierarchical precedence:

| Role | Level | Description | Bypass Rules |
|---|---|---|---|
| `superadmin` | Level 4 | System root administrator | Instant bypass across all permissions, roles, and app boundaries. Zero bitmask checks. |
| `admin` | Level 3 | Application administrator | Administrative access for managing users, tokens, and resources. |
| `normaluser` | Level 2 | Standard user | Standard authenticated privileges with default resource access. |
| `guest` | Level 1 | Restricted or unauthenticated | Explicitly denied access to protected endpoints by default. |

---

## 2. Multi-Role Support & Database Storage

In MBKAuthe v6, users are not restricted to a single role. A user has:
- A primary role stored in `mbkcore_users.role`.
- An optional array of secondary roles stored in `mbkcore_users.extra_roles` (e.g. `["author", "billing_admin"]`).

All assigned roles are stored on the role table (`mbkcore_roles`) along with their precomputed resource action bitmasks:

```sql
-- mbkcore_roles stores the bitmask map directly:
SELECT name, permissions FROM mbkcore_roles;
-- Returns:
-- name        | permissions
-- ------------+---------------------------------------------------
-- superadmin  | {}
-- admin       | {"global": 1, "users": 31, "billing": 15}
-- author      | {"global": 1, "articles": 15}
-- normaluser  | {"global": 1, "articles": 1}
```

When a user logs in, `attachSessionPermissions` aggregates all bitmasks across their primary role and `extra_roles` using bitwise OR (`combineResourceMasks`), making multi-role authorization instantaneous.

---

## 3. The `AuthorizationService` & `AuthContext`

The `authorizationService` provides pure, in-memory authorization evaluation without database queries:

```typescript
import { authorizationService, AuthContext } from "mbkauthe/core";

const context = new AuthContext({
  isAuthenticated: true,
  principal: {
    username: "alice",
    role: "normaluser",
    roles: ["normaluser", "author"],
    perms: { global: 1, articles: 15 },
  },
});

// 1. Role evaluation
console.log(authorizationService.hasRole(context, "author")); // true
console.log(authorizationService.hasAnyRole(context, ["admin", "superadmin"])); // false

// 2. AuthContext convenience methods
console.log(context.hasRole("author")); // true
console.log(context.isAdmin()); // false
console.log(context.isSuperadmin()); // false

// 3. Blacklist evaluation
console.log(authorizationService.isRoleDenied(context, "guest")); // false (alice is not guest)
```

---

## 4. Protecting Express Routes

### Standalone Role Middleware (`roleChk`)

Use `roleChk` to verify that an authenticated user possesses one of the allowed roles:

```typescript
import express from "express";
import { sessVal, roleChk } from "mbkauthe";

const app = express();

// Single allowed role:
app.get("/admin", sessVal, roleChk("admin"), (req, res) => {
  res.json({ message: "Welcome Admin" });
});

// Multiple allowed roles:
app.get("/editor", sessVal, roleChk(["admin", "author", "superadmin"]), (req, res) => {
  res.json({ message: "Content Editing Panel" });
});

// Blacklist a specific role (allow all except 'guest'):
app.post("/comments", sessVal, roleChk("*", "guest"), (req, res) => {
  res.json({ message: "Comment created" });
});
```

### Combined Session & Role Middleware (`sessRole`)

`sessRole` combines session authentication and role validation into a single step:

```typescript
import express from "express";
import { sessRole } from "mbkauthe";

const app = express();

// Protects route in one call
app.get("/superadmin/audit", sessRole("superadmin"), (req, res) => {
  res.json({ message: "Superadmin Audit Logs" });
});
```

---

## 5. Strict Session & Role Validation (`strictSessRole`)

For sensitive administrative actions requiring immediate database validation without caching shortcuts:

```typescript
import { strictSessRole } from "mbkauthe";

// Queries database directly to ensure active session and role
app.post("/admin/nuclear-reset", strictSessRole("superadmin"), handler);
```
