import { readFile } from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { describe, beforeAll, it, expect } from "vitest";

import { SqlitePool, PermissionRepository } from "../../dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = path.join(__dirname, "../../docs/schema/sqlite.sql");

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

describe("PermissionRepository — Bitmask Roles & Overrides", () => {
  it("creates, lists, and retrieves roles with bitmask permissions", async () => {
    const { repo } = createRepo();

    await repo.createRole("editor", {
      label: "Content Editor",
      description: "Can view and edit posts",
      permissions: { posts: 5, comments: 1 }, // 5 = view(1) | update(4)
    });

    const roles = await repo.listRoles();
    const editor = roles.find((r) => r.name === "editor");
    expect(editor).toBeDefined();
    expect(editor.label).toBe("Content Editor");
    expect(editor.permissions.posts).toBe(5);
    expect(editor.permissions.comments).toBe(1);

    const fetched = await repo.getRoleByName("editor");
    expect(fetched).toBeDefined();
    expect(fetched.name).toBe("editor");
    expect(fetched.permissions.posts).toBe(5);
  });

  it("updates role permissions", async () => {
    const { repo } = createRepo();

    await repo.createRole("moderator", {
      label: "Moderator",
      permissions: { comments: 1 },
    });

    await repo.setRolePermissions("moderator", { comments: 15 }); // full CRUD
    const updated = await repo.getRoleByName("moderator");
    expect(updated.permissions.comments).toBe(15);
  });

  it("deletes non-system roles", async () => {
    const { repo } = createRepo();

    await repo.createRole("temp_role", { label: "Temp" });
    await repo.deleteRole("temp_role");

    const fetched = await repo.getRoleByName("temp_role");
    expect(fetched).toBeNull();
  });

  it("computes effective permissions for a user from their roles", async () => {
    const { pool, repo } = createRepo();

    await repo.setRolePermissions("normaluser", { tasks: 1, profile: 5 });
    await insertUser(pool, { username: "alice", role: "normaluser" });

    const snapshot = await repo.computeEffectiveForUser("alice");
    expect(snapshot.role).toBe("normaluser");
    expect(snapshot.isSuperadmin).toBe(false);
    expect(snapshot.masks.tasks).toBe(1);
    expect(snapshot.masks.profile).toBe(5);
  });

  it("applies user overrides: adds allow mask and strips deny mask", async () => {
    const { pool, repo } = createRepo();

    await repo.createRole("editor", {
      permissions: { tasks: 15 }, // view(1), create(2), update(4), delete(8)
    });
    await insertUser(pool, { username: "bob", role: "editor" });

    await repo.setUserOverrides("bob", {
      allows: { projects: 1 },
      denies: { tasks: 8 }, // deny delete
    });

    const snapshot = await repo.computeEffectiveForUser("bob");
    expect(snapshot.masks.projects).toBe(1);
    expect(snapshot.masks.tasks).toBe(7); // 15 & ~8 = 7 (1 | 2 | 4)
  });

  it("returns instant superadmin snapshot without role lookups", async () => {
    const { repo } = createRepo();
    const snapshot = await repo.computeEffectiveForUser("root", "superadmin");
    expect(snapshot.isSuperadmin).toBe(true);
    expect(snapshot.role).toBe("superadmin");
  });

  it("invalidates memory cache when role or user changes", async () => {
    const { pool, repo } = createRepo();

    await repo.createRole("viewer", { permissions: { docs: 1 } });
    await insertUser(pool, { username: "carol", role: "viewer" });

    const firstSnap = await repo.computeEffectiveForUser("carol");
    expect(firstSnap.masks.docs).toBe(1);

    // Update role permissions and ensure cache is refreshed
    await repo.setRolePermissions("viewer", { docs: 7 });
    const secondSnap = await repo.computeEffectiveForUser("carol");
    expect(secondSnap.masks.docs).toBe(7);
  });
});
