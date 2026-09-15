# Dynamic Permission Catalogs in MBKAuthe v6

MBKAuthe v6 features a dynamic, manifest-driven permission catalog structured around `app:service:action` identifiers. Permissions can be declared in manifests, synced to the database, evaluated with wildcards, and enforced via Express middleware.

---

## 1. Defining Permissions (`definePermissions`)

Declare application permissions and default roles using `definePermissions`:

```typescript
import { definePermissions } from "mbkauthe/core";

export const CorePermissions = definePermissions({
  appKey: "portal",
  permissions: {
    users: {
      read: "View user directory",
      write: "Create and edit users",
      delete: "Delete user accounts",
    },
    billing: {
      view: "View invoices",
      charge: "Process payments",
    },
  },
  roles: {
    admin: {
      label: "Portal Administrator",
      permissions: ["portal:users:*", "portal:billing:*"],
    },
    member: {
      label: "Standard Member",
      permissions: ["portal:users:read", "portal:billing:view"],
    },
  },
});

// Generated type-safe permission strings:
console.log(CorePermissions.users.read);   // "portal:users:read"
console.log(CorePermissions.users.write);  // "portal:users:write"
console.log(CorePermissions.billing.charge); // "portal:billing:charge"
```

---

## 2. Syncing App Permissions to Database (`syncAppPermissions`)

On application startup, sync declared permissions to the database catalog:

```typescript
import { syncAppPermissions } from "mbkauthe/services";
import { CorePermissions } from "./permissions.js";

async function boot() {
  const result = await syncAppPermissions(CorePermissions);
  console.log(`Permission Sync Complete: ${result.synced} permissions registered.`);
}

boot();
```

---

## 3. Enforcing Permissions with `permChk` and `sessPerm`

### Using `permChk` (Permission Check)

```typescript
import express from "express";
import { sessVal, permChk } from "mbkauthe";
import { CorePermissions } from "./permissions.js";

const app = express();

app.post(
  "/api/users",
  sessVal,
  permChk(CorePermissions.users.write),
  (req, res) => {
    res.json({ message: "User created" });
  }
);
```

### Combined Middleware (`sessPerm`)

`sessPerm` validates session and verifies the requested permission in one step:

```typescript
import { sessPerm } from "mbkauthe";
import { CorePermissions } from "./permissions.js";

app.delete(
  "/api/users/:id",
  sessPerm(CorePermissions.users.delete),
  (req, res) => {
    res.json({ message: "User deleted" });
  }
);
```

---

## 4. Wildcard Matching & Direct Checks

Evaluate permissions programmatically using `hasPermission`:

```typescript
import { hasPermission } from "mbkauthe/core";

const user = {
  id: 1,
  username: "alice",
  role: "admin",
  overrides: {
    allows: ["portal:users:*"],
    denies: ["portal:users:delete"],
  },
};

console.log(hasPermission(user, "portal:users:read"));   // true
console.log(hasPermission(user, "portal:users:delete")); // false (Deny overrides Allow)
```
