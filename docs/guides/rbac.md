# Role-Based Access Control (RBAC) in MBKAuthe v6

MBKAuthe provides hierarchical Role-Based Access Control (RBAC) integrated into the session lifecycle and Express middleware routing.

---

## 1. Built-in Roles

MBKAuthe includes four standard global roles:

| Role | Hierarchy Level | Description |
|---|---|---|
| `superadmin` | Level 4 (Highest) | Full system bypass. Automatically passes all role checks and permissions. |
| `admin` | Level 3 | Administrative access for managing users, tokens, and application data. |
| `normaluser` | Level 2 | Standard authenticated user with default application privileges. |
| `guest` | Level 1 | Restricted or read-only access. |

---

## 2. The `RoleRegistry`

Roles and their associated permissions are managed in-memory via `RoleRegistry` and dynamically loaded from the database:

```typescript
import { RoleRegistry, defaultRoleRegistry } from "mbkauthe/core";

// Register custom role with permissions
defaultRoleRegistry.setRole("editor", [
  "blog:articles:create",
  "blog:articles:edit",
  "blog:comments:delete"
]);

// Check if role has a permission
const canEdit = defaultRoleRegistry.checkRoleHasPermission("editor", "blog:articles:edit");
console.log("Editor can edit:", canEdit); // true
```

---

## 3. Protecting Routes with `roleChk` and `sessRole`

### Using `roleChk` (Role Check Middleware)

`roleChk` verifies that the logged-in user possesses one of the allowed roles:

```typescript
import express from "express";
import { sessVal, roleChk } from "mbkauthe";

const app = express();

// Accessible only to 'superadmin' and 'admin'
app.get("/admin/settings", sessVal, roleChk(["superadmin", "admin"]), (req, res) => {
  res.json({ message: "Admin Settings Panel" });
});

// Blacklist a specific role (e.g. deny 'guest')
app.post("/comments", sessVal, roleChk("*", "guest"), (req, res) => {
  res.json({ message: "Comment created successfully" });
});
```

### Combined Session & Role Middleware (`sessRole`)

`sessRole` combines `validateSession` and `checkRolePermission` into a single middleware call:

```typescript
import { sessRole } from "mbkauthe";

app.get("/superadmin/audit", sessRole("superadmin"), (req, res) => {
  res.json({ message: "Superadmin Audit Logs" });
});
```
