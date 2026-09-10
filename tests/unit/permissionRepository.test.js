import { readFile } from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { describe, beforeAll, it, expect } from "vitest";

import { SqlitePool } from "../../lib/db/sqlitePool.js";
import { PermissionRepository } from "../../lib/db/PermissionRepository.js";
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

async function insertUser(pool, { username, role = "normaluser", active = 1, permissionTemplates = [] }) {
  await pool.query(
    `INSERT INTO mbkcore_users (username, role, is_active, permission_templates)
     VALUES (?, ?, ?, ?)`,
    [username, role, active, JSON.stringify(permissionTemplates)]
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

describe("PermissionRepository — templates", () => {
  it("creates/lists/updates/deletes templates", async () => {
    const { repo } = createRepo();
    await repo.createTemplate("Manager", ["blog:posts:create", "blog:posts:delete"]);
    await repo.createTemplate("Editor", ["blog:posts:edit"]);

    const templates = await repo.listTemplates();
    expect(templates.map((t) => t.name)).toEqual(["Editor", "Manager"]);

    await repo.updateTemplatePermissions("Manager", ["blog:posts:create", "blog:posts:publish"]);
    const manager = await repo.getTemplateByName("Manager");
    expect(manager.permissions).toEqual(["blog:posts:create", "blog:posts:publish"]);

    await repo.deleteTemplate("Editor");
    expect(await repo.getTemplateByName("Editor")).toBe(null);
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
  it("unions templates and applies allow/deny overrides", async () => {
    const { pool, repo } = createRepo();
    await insertUser(pool, { username: "alice", role: "editor" });

    await repo.createTemplate("Manager", ["blog:posts:create", "blog:posts:edit", "blog:posts:delete", "blog:posts:publish"]);
    await repo.createTemplate("Editor", ["blog:posts:edit", "blog:posts:publish", "blog:comments:moderate"]);

    await repo.setUserPermissionTemplates("alice", ["Manager", "Editor"]);
    await repo.setOverride("alice", "blog:posts:archive", "allow", "admin");
    await repo.setOverride("alice", "blog:posts:delete", "deny", "admin");

    const effective = await repo.computeEffectiveForUser("alice");
    expect(effective.templates).toEqual(["Manager", "Editor"]);
    expect(effective.allows).toEqual(
      expect.arrayContaining([
        "blog:posts:create",
        "blog:posts:edit",
        "blog:posts:publish",
        "blog:comments:moderate",
        "blog:posts:archive",
      ])
    );
    expect(effective.allows).not.toContain("blog:posts:delete");
    expect(effective.denies).toContain("blog:posts:delete");
    expect(effective.perm_version).toBeGreaterThanOrEqual(2);
  });

  it("returns empty permissions for a user with no templates/overrides", async () => {
    const { pool, repo } = createRepo();
    await insertUser(pool, { username: "carol" });
    const effective = await repo.computeEffectiveForUser("carol");
    expect(effective.allows).toEqual([]);
    expect(effective.denies).toEqual([]);
    expect(effective.templates).toEqual([]);
  });

  it("handles unknown template names gracefully (skips them)", async () => {
    const { pool, repo } = createRepo();
    await insertUser(pool, { username: "dave" });
    await repo.setUserPermissionTemplates("dave", ["Ghost"]);
    const effective = await repo.computeEffectiveForUser("dave");
    expect(effective.allows).toEqual([]);
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

  it("registers definePermissions() output and deactivates removed ones", async () => {
    const { repo } = createRepo();
    const { syncAppPermissions } = await import("../../lib/permissionRegistry.js");

    const Permissions = definePermissions(
      {
        posts: { create: "Create posts", edit: "Edit posts", delete: "Delete posts" },
        comments: { moderate: "Moderate comments" },
      },
      { appKey: "blog" }
    );

    const result = await syncAppPermissions(Permissions, { repository: repo, appKey: "blog" });
    expect(result).toMatchObject({ appKey: "blog", synced: 4, deactivated: 0 });
    expect(collectPermissions(Permissions)).toHaveLength(4);

    let catalog = await repo.listCatalogByApp("blog");
    expect(catalog).toHaveLength(4);
    expect(catalog.every((c) => c.is_active)).toBe(true);

    // Manifest shrinks: `comments.moderate` + `posts.delete` disappear.
    const Smaller = definePermissions(
      { posts: { create: "Create posts", edit: "Edit posts" } },
      { appKey: "blog" }
    );
    const result2 = await syncAppPermissions(Smaller, { repository: repo, appKey: "blog" });
    expect(result2.synced).toBe(2);
    expect(result2.deactivated).toBe(2);

    catalog = await repo.listCatalogByApp("blog");
    expect(catalog).toHaveLength(4);
    const inactive = catalog.filter((c) => !c.is_active).map((c) => c.permission).sort();
    expect(inactive).toEqual(["blog:comments:moderate", "blog:posts:delete"]);
  });
});
