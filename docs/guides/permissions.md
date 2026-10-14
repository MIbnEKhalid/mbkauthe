# Numeric Bitmask Permissions & Authorization Engine in MBKAuthe v6

MBKAuthe v6 features a **pure numeric bitmask permission engine** that eliminates runtime database lookups, regex parsing, and string allocations. Permission evaluation executes in a **single CPU bitwise cycle (< 1ns)**, while sessions store precomputed resource action masks directly in memory.

---

## 1. Core Architecture: Why Numeric Bitmasks?

Traditional permission systems match strings (`"users:read"`) or evaluate wildcards against database tables on every request. MBKAuthe encodes every resource action as a deterministic 31-bit integer flag.

### Key Advantages:
- **Sub-Nanosecond Evaluation**: Checking access requires only `(userMask & requiredMask) === requiredMask`.
- **Zero Request-Time DB Queries**: Effective permissions are hydrated once at session creation and attached to `req.session.user.perms`.
- **Deterministic Precedence**: Role masks are combined via bitwise `OR`, and explicit user denials strip bits via bitwise `AND NOT` (`& ~denyMask`).
- **Compact Persistence**: Instead of thousands of junction rows across multiple tables, roles store a single JSON/text bitmask map in `mbkcore_roles.permissions` (e.g. `{"global": 1, "tasks": 15}`).

---

## 2. Standard Action Bits

Each bit position within an integer represents an action on a given resource:

```typescript
export const StandardActionBits = {
  VIEW: 1 << 0,   // 1  (0b00001) - Read / List / View / Get
  CREATE: 1 << 1, // 2  (0b00010) - Create / Add / Upload
  UPDATE: 1 << 2, // 4  (0b00100) - Edit / Modify / Patch
  DELETE: 1 << 3, // 8  (0b01000) - Delete / Destroy / Remove
  MANAGE: 1 << 4, // 16 (0b10000) - Administrative / Configuration
} as const;
```

Custom resource actions automatically start at bit `1 << 5` (`32`) up to bit 30 (`0x7fffffff`).

---

## 3. Defining Resources & Permissions

MBKAuthe provides `defineResource` and `defineResources` (aliased as `definePermissions`) to generate typed, immutable `ActionDescriptor` objects.

### Defining Individual Resources (`defineResource`)

```typescript
import { defineResource, StandardActionBits } from "mbkauthe/core";

export const Tasks = defineResource("tasks", {
  view: "View tasks",            // Automatically assigns StandardActionBits.VIEW (1)
  create: "Create new tasks",    // Automatically assigns StandardActionBits.CREATE (2)
  update: "Modify tasks",        // Automatically assigns StandardActionBits.UPDATE (4)
  delete: "Remove tasks",        // Automatically assigns StandardActionBits.DELETE (8)
  assign: "Assign task to user", // Custom action -> assigned 1 << 5 (32)
});

console.log(Tasks.actions.view.mask);   // 1
console.log(Tasks.actions.assign.mask); // 32
console.log(Tasks.allMask);             // 47 (1 | 2 | 4 | 8 | 32)
console.log(Tasks.actions["*"].mask);   // 47 (Wildcard access to all actions)
```

### Defining Complete App Manifests (`definePermissions`)

Consuming applications declare all resources and default role bitmasks together:

```typescript
import { definePermissions } from "mbkauthe/core";

export const AppPermissions = definePermissions({
  users: {
    view: "View user profiles",
    create: "Invite new users",
    update: "Update user details",
    delete: "Deactivate user accounts",
  },
  billing: {
    view: "View billing history",
    manage: "Manage subscription plans",
    export: "Export financial statements",
  },
}, {
  app: "portal",
  roles: {
    superadmin: ["*"], // Wildcard granting all actions across all declared resources
    admin: {
      label: "Portal Admin",
      description: "Full portal management except system roots",
      permissions: ["users:*", "billing:*"],
    },
    member: {
      label: "Standard Member",
      permissions: ["users:view", "billing:view"],
    },
  },
});

// Type-safe ActionDescriptor usage:
console.log(AppPermissions.users.view.mask); // 1
console.log(String(AppPermissions.users.view)); // "portal:users:view"
console.log(Number(AppPermissions.users.view)); // 1
```

---

## 4. Multi-Role Aggregation & User Overrides

MBKAuthe resolves a user's effective permissions by combining their primary role (`user.role`), additional assigned roles (`user.extra_roles`), and explicit user overrides (`user.perm_overrides`).

### Bitwise Mask Combination
```typescript
import { combineResourceMasks, applyOverrides, hasAction, StandardActionBits } from "mbkauthe/core";

// 1. Roles assigned to user
const roleA = { tasks: 1, documents: 2 }; // tasks: view (1), documents: create (2)
const roleB = { tasks: 4, reports: 1 };   // tasks: update (4), reports: view (1)

// Combine via bitwise OR:
const baseMasks = combineResourceMasks(roleA, roleB);
// => { tasks: 5, documents: 2, reports: 1 } (tasks: 1 | 4 = 5)

// 2. Explicit User Overrides
const overrides = {
  allows: { documents: 1 }, // Grant documents: view (1)
  denies: { tasks: 4 },     // Deny tasks: update (4)
};

// Formula: (baseMask | userAllows) & ~userDenies
const effectiveMasks = applyOverrides(baseMasks, overrides);
// => { tasks: 1, documents: 3, reports: 1 }

// 3. Nanosecond Check:
console.log(hasAction(effectiveMasks.tasks, StandardActionBits.VIEW));   // true
console.log(hasAction(effectiveMasks.tasks, StandardActionBits.UPDATE)); // false (stripped by deny)
```

---

## 5. Synchronizing Permissions at Startup (`syncAppPermissions`)

At application startup, invoke `syncAppPermissions` to persist declared role masks into `mbkcore_roles`:

```typescript
import { syncAppPermissions } from "mbkauthe/services";
import { AppPermissions } from "./permissions.js";

async function bootstrap() {
  const result = await syncAppPermissions(AppPermissions);
  console.log(`[auth] Permissions Synced for ${result.appKey}: ${result.rolesSynced} roles updated.`);
}

bootstrap();
```

Unlike legacy versions, `syncAppPermissions` does not perform complex diffs against hundreds of catalog rows. It updates the `mbkcore_roles.permissions` JSON column directly, ensuring fast startup times.

---

## 6. Request Authorization with `AuthContext`

During incoming requests, MBKAuthe wraps the authenticated principal in an `AuthContext`:

```typescript
import { AuthContext } from "mbkauthe/core";
import { AppPermissions } from "./permissions.js";

// Access AuthContext from express request:
const auth = (req as any).authContext as AuthContext;

// Check single permission via ActionDescriptor:
if (auth.can(AppPermissions.users.create)) {
  // User is allowed to invite users
}

// Check with resource string and numeric bitmask:
if (auth.hasPermission("users", 1)) {
  // User can view users
}

// Check multiple permissions:
const canManageAll = auth.hasAllPermissions(
  AppPermissions.users.view,
  AppPermissions.billing.view
);

// Check if user has ANY of the permissions:
const hasAnyAccess = auth.hasAnyPermission(
  AppPermissions.users.delete,
  AppPermissions.billing.manage
);
```

### SuperAdmin Instant Bypass
If `auth.isSuperadmin()` is true, all permission checks, role checks, and application boundaries return `true` immediately without evaluating bitmasks or performing database queries.

---

## 7. Express Middleware: `permChk` & `sessPerm`

Protect Express routes directly using either standalone permission checks or combined session and permission pipelines:

### Standalone Permission Check (`permChk`)

Use `permChk` when `sessVal` is already applied earlier in the middleware chain:

```typescript
import express from "express";
import { sessVal, permChk } from "mbkauthe";
import { AppPermissions } from "./permissions.js";

const router = express.Router();

router.post(
  "/users",
  sessVal,
  permChk(AppPermissions.users.create),
  (req, res) => {
    res.json({ message: "User created" });
  }
);
```

### Combined Session & Permission Pipeline (`sessPerm`)

`sessPerm` verifies session authentication and validates the bitmask permission in a single call:

```typescript
import express from "express";
import { sessPerm } from "mbkauthe";
import { AppPermissions } from "./permissions.js";

const app = express();

// Requires active session AND delete permission on users
app.delete(
  "/api/users/:id",
  sessPerm(AppPermissions.users.delete),
  (req, res) => {
    res.json({ message: "User deleted" });
  }
);

// String shorthand also supported:
app.get(
  "/api/users",
  sessPerm("users.view"),
  (req, res) => {
    res.json({ users: [] });
  }
);
```

If authorization fails:
- **API Clients (`Accept: application/json`)**: Receives `403 Forbidden` with error code `INSUFFICIENT_PERMISSIONS` and the required resource/action.
- **Browser Clients**: Renders the 403 Access Denied template with a redirect link to the dashboard.
