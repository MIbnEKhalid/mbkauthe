import { readFile } from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { describe, beforeAll, it, expect } from "vitest";

import { SqlitePool } from "../../lib/db/sqlitePool.js";
import { PermissionRepository } from "../../lib/repositories/PermissionRepository.js";
import { definePermissions, collectPermissions } from "../../lib/permissions.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = path.join(__dirname, "../../docs/schema/db.sqlite.sql");

let schemaSql;

beforeAll(async () => {
  schemaSql = await readFile(SCHEMA_PATH, "utf8");
});

function createRepo() {
  const pool = new SqlitePool(":memory:");
  pool.execScript(schemaSql);
  return { pool, repo: new PermissionRepository({ db: pool, dialect: { name: "sqlite" } }) };
}

async function insertUser(pool, { username, role = "normaluser", active = 1 }) {
  await pool.query(
    `INSERT INTO mbkcore_users (username, role, is_active)
     VALUES (?, ?, ?)`,
    [username, role, active]
  );
}

describe("PermissionRepository — catalog", () => {
  it("upsert + list catalog", async () => {
    const { repo } = createRepo();
    await repo.upsertCatalogPermission({ appKey: "blog", serviceKey: "posts", actionKey: "create", label: "Create posts" });
    await repo.upsertCatalogPermission({ appKey: "blog", serviceKey: "posts", actionKey: "delete", label: "Delete posts" });

    const catalog = await repo.listCatalogByApp("blog");
    expect(catalog).toHaveLength(2);
    expect(catalog[0]).toMatchObject({ app_key: "blog", service_key: "posts", permission: "blog:posts:create", is_active: true });
  });

  it("syncCatalogForApp is idempotent and soft-deactivates removed permissions", async () => {
    const { repo } = createRepo();
    await repo.syncCatalogForApp("blog", [
      { serviceKey: "posts", actionKey: "create", label: "Create" },
      { serviceKey: "posts", actionKey: "delete", label: "Delete" },
    ]);

    // Run again with same set — still 2 active, idempotent.
    await repo.syncCatalogForApp("blog", [
      { serviceKey: "posts", actionKey: "create", label: "Create" },
      { serviceKey: "posts", actionKey: "delete", label: "Delete" },
    ]);
    let catalog = await repo.listCatalogByApp("blog");
    expect(catalog).toHaveLength(2);
    expect(catalog.every((c) => c.is_active)).toBe(true);

    // Remove `delete` from the manifest -> deactivated, NOT deleted.
    await repo.syncCatalogForApp("blog", [{ serviceKey: "posts", actionKey: "create", label: "Create" }]);
    catalog = await repo.listCatalogByApp("blog");
    expect(catalog).toHaveLength(2);
    const deleteEntry = catalog.find((c) => c.action_key === "delete");
    expect(deleteEntry.is_active).toBe(false);
    expect(catalog.find((c) => c.action_key === "create").is_active).toBe(true);
  });

  it("lookupCatalogPermission checks existence + active state", async () => {
    const { repo } = createRepo();
    await repo.syncCatalogForApp("blog", [{ serviceKey: "posts", actionKey: "create", label: "Create" }]);
    expect(await repo.isCatalogPermissionActive("blog:posts:create")).toBe(true);
    expect(await repo.isCatalogPermissionActive("blog:posts:nope")).toBe(false);
    expect(await repo.lookupCatalogPermission("malformed")).toBe(null);
  });
});

describe("PermissionRepository — roles", () => {
  it("creates/lists/updates/deletes unified roles", async () => {
    const { repo } = createRepo();
    await repo.createRole("manager", ["blog:posts:create", "blog:posts:delete"], { label: "Manager" });
    await repo.createRole("editor", ["blog:posts:edit"], { label: "Editor" });

    const roles = await repo.listRoles();
    expect(roles.map((r) => r.name)).toEqual(
      expect.arrayContaining(["admin", "author", "editor", "manager", "normaluser", "superadmin"])
    );

    await repo.setRolePermissions("manager", ["blog:posts:create", "blog:posts:publish"]);
    const manager = await repo.getRoleByName("manager");
    expect(manager.permissions).toEqual(["blog:posts:create", "blog:posts:publish"]);

    await repo.deleteRole("editor");
    expect(await repo.getRoleByName("editor")).toBe(null);
  });

  it("contributes permissions to a unified role across apps", async () => {
    const { repo } = createRepo();
    await repo.contributeRolePermissions("editor", ["blog:posts:create", "blog:posts:edit"]);
    await repo.contributeRolePermissions("editor", ["chat:messages:send", "chat:files:upload"]);

    const editor = await repo.getRoleByName("editor");
    expect(editor.permissions).toEqual(
      expect.arrayContaining(["blog:posts:create", "blog:posts:edit", "chat:messages:send", "chat:files:upload"])
    );
  });
});

describe("PermissionRepository — overrides", () => {
  it("sets, updates, lists, removes per-user overrides", async () => {
    const { pool, repo } = createRepo();
    await insertUser(pool, { username: "alice" });
    await insertUser(pool, { username: "bob" });
    await repo.setOverride("alice", "blog:posts:delete", "deny", "admin");
    await repo.setOverride("alice", "blog:posts:archive", "allow", "admin");
    await repo.setOverride("bob", "blog:posts:create", "allow", "admin");

    let overrides = await repo.listOverridesForUser("alice");
    expect(overrides).toHaveLength(2);
    expect(overrides.map((o) => o.permission)).toEqual(["blog:posts:archive", "blog:posts:delete"]);

    // Upsert existing override.
    await repo.setOverride("alice", "blog:posts:delete", "allow", "admin");
    overrides = await repo.listOverridesForUser("alice");
    expect(overrides.find((o) => o.permission === "blog:posts:delete").effect).toBe("allow");

    await repo.removeOverride("alice", "blog:posts:delete");
    overrides = await repo.listOverridesForUser("alice");
    expect(overrides).toHaveLength(1);

    await repo.clearOverridesForUser("alice");
    expect(await repo.listOverridesForUser("alice")).toHaveLength(0);
    // Bob unaffected.
    expect(await repo.listOverridesForUser("bob")).toHaveLength(1);
  });
});

describe("PermissionRepository — effective permissions for a user", () => {
  it("assigns user role and applies allow/deny overrides", async () => {
    const { pool, repo } = createRepo();
    await repo.createRole("manager", ["blog:posts:create", "blog:posts:edit", "blog:posts:delete", "blog:posts:publish"]);
    await insertUser(pool, { username: "alice", role: "manager" });

    await repo.setOverride("alice", "blog:posts:archive", "allow", "admin");
    await repo.setOverride("alice", "blog:posts:delete", "deny", "admin");

    const snapshot = await repo.computeEffectiveForUser("alice");
    expect(snapshot.roles).toContain("manager");
    expect(snapshot.effective.allows).toEqual(
      expect.arrayContaining([
        "blog:posts:create",
        "blog:posts:edit",
        "blog:posts:publish",
        "blog:posts:archive",
      ])
    );
    expect(snapshot.effective.allows).not.toContain("blog:posts:delete");
    expect(snapshot.effective.denies).toContain("blog:posts:delete");
    expect(snapshot.perm_version).toBeGreaterThanOrEqual(1);
  });

  it("returns empty permissions for a user with no permissions in role or overrides", async () => {
    const { pool, repo } = createRepo();
    await insertUser(pool, { username: "carol", role: "normaluser" });
    const snapshot = await repo.computeEffectiveForUser("carol");
    expect(snapshot.effective.allows).toEqual([]);
    expect(snapshot.effective.denies).toEqual([]);
    expect(snapshot.roles).toEqual(["normaluser"]);
  });
});

describe("syncAppPermissions integration", () => {
  it("does not allow an app sync to manage global permissions", async () => {
    const { repo } = createRepo();
    const { syncAppPermissions } = await import("../../lib/permissionRegistry.js");
    const Global = definePermissions({ basic: { access: "Basic global access" } }, { appKey: "global" });

    await expect(syncAppPermissions(Global, { repository: repo, appKey: "global" }))
      .rejects.toThrow("Global permissions are built into the catalog");

    const builtIn = await repo.lookupCatalogPermission("global:basic:access");
    expect(builtIn).toMatchObject({ permission: "global:basic:access", is_active: true });
    await repo.syncCatalogForApp("global", []);
    expect(await repo.isCatalogPermissionActive("global:basic:access")).toBe(true);
  });

  it("registers definePermissions() output with roles and deactivates removed ones", async () => {
    const { repo } = createRepo();
    const { syncAppPermissions } = await import("../../lib/permissionRegistry.js");

    const Permissions = definePermissions(
      {
        posts: { create: "Create posts", edit: "Edit posts", delete: "Delete posts" },
        comments: { moderate: "Moderate comments" },
      },
      {
        appKey: "blog",
        roles: {
          editor: ["posts:create", "posts:edit", "comments:moderate"],
        },
      }
    );

    const result = await syncAppPermissions(Permissions, { repository: repo, appKey: "blog" });
    expect(result).toMatchObject({ appKey: "blog", synced: 4, deactivated: 0, rolesSynced: 1 });
    expect(collectPermissions(Permissions)).toHaveLength(4);

    const editorRole = await repo.getRoleByName("editor");
    expect(editorRole.permissions).toEqual(
      expect.arrayContaining(["blog:posts:create", "blog:posts:edit", "blog:comments:moderate"])
    );

    let catalog = await repo.listCatalogByApp("blog");
    expect(catalog).toHaveLength(4);
    expect(catalog.every((c) => c.is_active)).toBe(true);
  });
});
