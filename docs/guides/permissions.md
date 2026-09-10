# Dynamic Catalog-Driven Permissions

[Back to docs index](../README.md) | [Back to project README](../../README.md)

MBKAuthe provides a **dynamic, fine-grained, permission-based authorization
system** on top of the existing role/session model. Permissions use the form:

```text
app:service:action
```

Examples:

```text
blog:posts:create
blog:posts:edit
blog:posts:delete
blog:comments:moderate
dns:records:write
```

The reserved `global` namespace is shared by every host application. It is
seeded and repaired by MBKAuthe itself, so it is not part of application
manifest synchronization:

```js
import { GlobalPermissions, defineGlobalPermissions } from "mbkauthe";

GlobalPermissions.basic.access; // -> "global:basic:access"

export const SharedPermissions = defineGlobalPermissions({
  pages: { view: "View shared pages" },
});
```

Use a global permission when the same access rule applies across applications;
use `definePermissions()` for application-owned pages and features.
For the built-in baseline permission, host routes can use the shorthand without
importing `GlobalPermissions`:

```js
router.get("/dashboard", sessPerm("basic.access"), renderDashboard);
```

> **`service` is only a logical permission/resource identifier.** It does NOT
> imply that a host application must have a `services/` directory or service
> class. An application may implement `posts` via `PostsController`,
> `PostsService`, `PostsModule`, or directly in route handlers — all valid.

---

## 1. Architecture rules

| # | Rule |
| :- | :--- |
| 1 | **Host apps define permissions** (a `permissions.js` manifest). |
| 2 | **mbkauthe resolves and enforces permissions** (`definePermissions`, `syncAppPermissions`, `hasPermission`, `permChk`, `sessPerm`). |
| 3 | **mbkcore manages** the catalog, roles/templates, users, overrides, and the catalog UI. |
| 4 | **Roles/templates are permission bundles**, not hardcoded authorization logic. |
| 5 | **SuperAdmin bypasses permission checks completely.** |
| 6 | **User overrides can grant or deny** individual permissions. |
| 7 | **Deny always wins.** |
| 8 | **The service segment is only a logical identifier.** |
| 9 | **Permission checks never query the database** on the request path. |
| 10 | **New permissions are discovered automatically** from application code. |
| 11 | **No raw permission strings** in route/controller authorization code (`Permissions.posts.delete`). |
| 12 | **Permission computation happens at login/session refresh**, not every request. |

---

## 2. Host applications define permissions

Each host application defines its own permissions in code:

```js
// permissions.js
import { definePermissions } from "mbkauthe";

export const Permissions = definePermissions({
  posts: {
    create: "Create posts",
    edit: "Edit posts",
    delete: "Delete posts",
    publish: "Publish posts",
  },
  comments: {
    moderate: "Moderate comments",
    delete: "Delete comments",
  },
});
```

`definePermissions()` automatically uses the application's configured app key
(`APP_NAME` / `mbkautheVar.APP_NAME`), so:

```js
Permissions.posts.delete; // -> "blog:posts:delete"
```

Applications must NOT hard-code raw permission strings in route/controller code:

```js
// ❌ Bad — raw literal, no discoverability
permChk("blog:posts:delete")

// ✅ Good
permChk(Permissions.posts.delete)
sessPerm(Permissions.posts.delete)
```

---

## 3. Automatic permission catalog

Call `syncAppPermissions(Permissions)` once during application startup (for
example at the top of `src/server.js` before `listen()`):

```js
import { syncAppPermissions } from "mbkauthe";
import { Permissions } from "./permissions.js";

await syncAppPermissions(Permissions);
```

This registers every declared permission in mbkcore's catalog
(`mbkcore_permission_catalog`). If a permission disappears from the manifest,
the matching catalog row is marked `is_active = false` (never deleted). The
manifest is the **source of truth for valid application permissions** — no
administrator should manually create catalog permissions.

`syncAppPermissions` is idempotent and safe to run repeatedly. It is an
administrative/startup operation, never part of the request authorization path.

---

## 4. Middleware reference

### `hasPermission(user, required)`

Pure, synchronous, in-memory authorization decision. Never touches the
database or the network.

```js
import { hasPermission } from "mbkauthe";

if (hasPermission(req.session.user, Permissions.posts.delete)) {
  // allowed
}
```

Wildcards are supported in any segment (`app`, `service`, `action` may be `*`):

```text
blog:*:read
*:posts:delete
*:*:read
```

Decision order:

```text
SuperAdmin -> allow
deny       -> deny     (deny always wins)
allow      -> allow
otherwise  -> deny
```

### `sessPerm(requiredPermission)`

Follows the `sessRole()` style: validates the session, then checks the
permission. Compose with the existing middleware:

```js
import { sessPerm } from "mbkauthe";
import { Permissions } from "./permissions.js";

app.delete("/api/posts/:id", sessPerm(Permissions.posts.delete), deletePost);
```

Unauthorized requests receive **HTTP 403** using mbkauthe's existing
JSON-vs-HTML error behavior.

### `permChk(requiredPermission)`

Composable permission guard (mirrors `roleChk`): chain it after session
validation.

```js
import { sessVal, permChk } from "mbkauthe";

app.delete("/api/posts/:id", sessVal, permChk(Permissions.posts.delete), deletePost);
```

### Combining with existing role checks

Keep existing role checks where they still carry semantic meaning:

```js
router.delete(
  "/posts/:id",
  sessRole("admin"),
  sessPerm(Permissions.posts.delete),
  deletePost
);
```

All existing middleware (`sessVal`, `roleChk`, `sessRole`, `strictSessVal`,
`strictSessRole`, `strictValidateSession`, `strictValidateSessionAndRole`,
`authenticate`, `validateSessionAndRole`) continues to work unchanged.

---

## 5. Effective permissions & the session

Authorization stays completely **in-memory** during normal requests:

```text
Request
  ↓
Session
  ↓
in-memory permissions (req.session.user.permissions)
  ↓
permission check
  ↓
Controller
```

At login, session creation, explicit session reload, and
`reloadSessionUser()`, mbkauthe computes the user's effective permissions and
stores them as:

```js
req.session.user.permissions = {
  allows: ["blog:posts:create", "blog:posts:edit", ...],
  denies: ["blog:posts:delete"],
};
```

**No database query occurs during the request for authorization.**

### Effective permission calculation

A role/template is a **named reusable permission bundle** (e.g. `Manager`,
`Editor`, `Moderator`, `Viewer`). Users are assigned one or more templates; the
effective permission set is the union of all assigned template permissions with
per-user overrides applied:

```text
template permissions
        ↓
      UNION
        ↓
user deny overrides
        ↓
user allow overrides
        ↓
effective permissions
```

Rules:

1. Template permissions are inherited automatically.
2. Multiple templates are combined (union).
3. Explicit user `deny` overrides inherited/allowed permissions.
4. Explicit user `allow` grants a permission not otherwise inherited.
5. **Deny always wins over allow.**

Example — a user assigned the `Manager` template:

```text
Role: Manager

blog:posts:create
blog:posts:edit
blog:posts:delete
blog:posts:publish
```

with overrides:

```text
DENY  blog:posts:delete
ALLOW blog:posts:archive
```

Effective result:

```text
blog:posts:create
blog:posts:edit
blog:posts:publish
blog:posts:archive
```

---

## 6. SuperAdmin

`superadmin` is a special system-level bypass. When
`req.session.user.role === "superadmin"`, permission checks succeed
immediately — SuperAdmin is never required to carry stored permissions and no
large permission set is generated for it.

```js
// hasPermission begins with:
if (user?.role === "superadmin") return true;
```

---

## 7. Permission changes & session invalidation

When an administrator changes a user's template assignment, a role's
permissions, or a user's overrides, mbkcore increments that user's
`perm_version`. Where feasible the active session is reloaded; otherwise the
change takes effect at the next login/session refresh. mbkauthe never performs
a `perm_version` database lookup on every request.

---

## 8. API tokens & permissions

API tokens can be scoped to an explicit permission allow-list. When a token is
used for authentication, its `permissions` list is attached to the synthetic
user as `permissions.allows`, so `permChk` / `sessPerm` guards evaluate against
the token's own permissions:

```json
{ "permissions": ["portal:dns:view"] }
```

The `app:service:action` form already encodes both the target application and the
operation, so tokens no longer carry a separate read/write scope or allowed-apps
list — the permission list is the single source of truth.

- **Cap semantics** — a non-superadmin user can only grant a token permissions
they themselves hold. `intersectPermissions(ownerPermissions, requested)` computes
the capped set, and `POST /api/token` rejects permissions the caller lacks.
- **At least one permission** is required when creating a token.
- **SuperAdmin bypass is unchanged** — a superadmin token keeps full permission
access regardless of the stored list; the list is declarative for such tokens.
- **Legacy tokens** (no stored permission list) carry no effective permissions,
preserving their previous behaviour until recreated.

CLI/device-flow tokens issued from an **API token profile** are capped at the
approving user's effective permissions (`intersectPermissions`) before the token
row is written; profile permissions must exist in the active catalog.

---

## 9. API surface

| Export | Purpose |
| :--- | :--- |
| `definePermissions(manifest[, { appKey }])` | Build the `Permissions` object (`app:service:action` strings). |
| `syncAppPermissions(Permissions[, { appKey }])` | Idempotently sync a manifest into the catalog. |
| `hasPermission(user, required)` | Pure in-memory authorization decision. |
| `intersectPermissions(held, requested)` | Cap a requested permission set to the permissions the owner holds (used for API tokens). |
| `permChk(requiredPermission)` | Middleware permission guard (after session validation). |
| `sessPerm(requiredPermission)` | Session-validating permission guard. |
| `PermissionRepository` / `permissionRepository` | Catalog/template/override persistence + effective-permission computation. |
| `attachSessionPermissions(sessionUser, username)` | Compute + cache effective permissions on a session user. |
