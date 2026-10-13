import { describe, it, expect } from "vitest";
import { definePermissions, hasPermission, buildEffectivePermissions, collectPermissions, collectRoles, intersectPermissions, defineGlobalPermissions, GlobalPermissions, resolvePermission, RoleRegistry, mbkautheVar } from "../../dist/index.js";

describe("definePermissions", () => {
  it("resolves nested service/action access to descriptor nodes with numeric IDs and string keys", () => {
    const Permissions = definePermissions(
      {
        posts: { create: "Create posts", edit: "Edit posts", delete: "Delete posts" },
        comments: { moderate: "Moderate comments" },
      },
      { appKey: "blog" }
    );

    expect(Permissions.posts.create.key).toBe("blog:posts:create");
    expect(Permissions.posts.edit.key).toBe("blog:posts:edit");
    expect(Permissions.posts.delete.key).toBe("blog:posts:delete");
    expect(Permissions.comments.moderate.key).toBe("blog:comments:moderate");

    expect(typeof Permissions.posts.create.id).toBe("number");
    expect(Permissions.posts.create.id).toBeGreaterThan(0);
    expect(Number(Permissions.posts.create)).toBe(Permissions.posts.create.id);
  });

  it("auto-prefixes with the configured app key (mbkautheVar.APP_NAME)", () => {
    const Permissions = definePermissions({ posts: { delete: "Delete posts" } });
    const app = (mbkautheVar.APP_NAME || process.env.APP_NAME || "").toLowerCase();
    expect(Permissions.posts.delete.key).toBe(`${app}:posts:delete`);
    expect(Permissions.posts.delete.id).toBeGreaterThan(0);
  });

  it("collects all declared permissions with labels and numeric IDs", () => {
    const Permissions = definePermissions(
      { posts: { create: "Create posts", delete: "Delete posts" } },
      { appKey: "blog" }
    );
    const collected = collectPermissions(Permissions);
    expect(collected).toHaveLength(2);
    expect(collected[0]).toMatchObject({
      appKey: "blog",
      serviceKey: "posts",
      actionKey: "create",
      key: "blog:posts:create",
      label: "Create posts",
    });
    expect(collected[0].id).toBeGreaterThan(0);
  });

  it("collects declared roles from manifest and expands wildcards to numeric ID arrays", () => {
    const Permissions = definePermissions(
      { posts: { create: "Create posts", edit: "Edit posts" } },
      {
        appKey: "blog",
        roles: {
          admin: ["*"],
          editor: ["posts:create", "posts:edit"],
        },
      }
    );

    const roles = collectRoles(Permissions);
    expect(roles).toHaveLength(2);
    expect(roles.find((r) => r.name === "admin").permissions).toEqual([
      Permissions.posts.create.id,
      Permissions.posts.edit.id,
    ]);
    expect(roles.find((r) => r.name === "editor").permissions).toEqual([
      Permissions.posts.create.id,
      Permissions.posts.edit.id,
    ]);
  });
});

describe("global permissions", () => {
  it("uses the reserved global namespace for every app", () => {
    const Permissions = defineGlobalPermissions({ pages: { view: "View pages" } });
    expect(Permissions.pages.view.key).toBe("global:pages:view");
    expect(GlobalPermissions.basic.access.key).toBe("global:basic:access");
    expect(GlobalPermissions.basic.access.id).toBe(1);
  });

  it("resolves basic.access shorthand to the numeric ID of global basic access", () => {
    expect(resolvePermission("basic.access")).toBe(1);
    expect(resolvePermission("global:basic:access")).toBe(1);
  });
});

describe("hasPermission — SuperAdmin bypass", () => {
  it("returns true for superadmin with no stored permissions", () => {
    const user = { role: "superadmin" };
    expect(hasPermission(user, "blog:posts:delete")).toBe(true);
    expect(hasPermission(user, 999)).toBe(true);
  });

  it("returns true for superadmin even with an empty permission set", () => {
    const user = { role: "superadmin", overrides: { allows: [], denies: [] } };
    expect(hasPermission(user, "blog:posts:delete")).toBe(true);
    expect(hasPermission(user, 999)).toBe(true);
  });

  it("returns true for SUPERADMIN in user.roles", () => {
    expect(hasPermission({ role: "member", roles: ["SuperAdmin"] }, "x:y:z")).toBe(true);
  });
});

describe("hasPermission — RoleRegistry & unified roles", () => {
  const customRegistry = new RoleRegistry();
  const BlogPerms = definePermissions(
    {
      posts: { create: "Create posts", edit: "Edit posts", delete: "Delete posts", view: "View posts" },
      comments: { moderate: "Moderate comments" },
    },
    { appKey: "blog" }
  );

  customRegistry.setRole("editor", [BlogPerms.posts.create, BlogPerms.posts.edit, BlogPerms.comments.moderate]);
  customRegistry.setRole("viewer", [BlogPerms.posts.view]);

  it("allows when user's role grants permission (by descriptor, string, or number)", () => {
    const user = { role: "editor" };
    expect(hasPermission(user, BlogPerms.posts.create, customRegistry)).toBe(true);
    expect(hasPermission(user, "blog:posts:create", customRegistry)).toBe(true);
    expect(hasPermission(user, BlogPerms.posts.create.id, customRegistry)).toBe(true);
    expect(hasPermission(user, BlogPerms.posts.edit, customRegistry)).toBe(true);
  });

  it("denies when user's role lacks permission", () => {
    const user = { role: "editor" };
    expect(hasPermission(user, BlogPerms.posts.delete, customRegistry)).toBe(false);
  });

  it("unions multiple roles in user.roles", () => {
    const user = { role: "viewer", roles: ["editor"] };
    expect(hasPermission(user, BlogPerms.posts.view, customRegistry)).toBe(true);
    expect(hasPermission(user, BlogPerms.posts.create, customRegistry)).toBe(true);
  });
});

describe("hasPermission — allow & deny overrides", () => {
  const customRegistry = new RoleRegistry();
  const BlogPerms = definePermissions(
    {
      posts: { create: "Create posts", edit: "Edit posts", delete: "Delete posts", publish: "Publish posts" },
    },
    { appKey: "blog" }
  );

  customRegistry.setRole("editor", [BlogPerms.posts.create, BlogPerms.posts.edit, BlogPerms.posts.delete]);

  it("applies deny override to remove role-granted permission", () => {
    const user = {
      role: "editor",
      overrides: {
        denies: [BlogPerms.posts.delete.id],
        allows: [],
      },
    };
    expect(hasPermission(user, BlogPerms.posts.create, customRegistry)).toBe(true);
    expect(hasPermission(user, BlogPerms.posts.delete, customRegistry)).toBe(false);
  });

  it("applies allow override to grant exceptional permission", () => {
    const user = {
      role: "editor",
      overrides: {
        allows: [BlogPerms.posts.publish.id],
        denies: [],
      },
    };
    expect(hasPermission(user, BlogPerms.posts.publish, customRegistry)).toBe(true);
  });

  it("deny always wins over allow override", () => {
    const user = {
      role: "editor",
      overrides: {
        allows: [BlogPerms.posts.delete.id],
        denies: [BlogPerms.posts.delete.id],
      },
    };
    expect(hasPermission(user, BlogPerms.posts.delete, customRegistry)).toBe(false);
  });
});

describe("buildEffectivePermissions", () => {
  const customRegistry = new RoleRegistry();
  const BlogPerms = definePermissions(
    {
      posts: { create: "Create posts", edit: "Edit posts", delete: "Delete posts", publish: "Publish posts", archive: "Archive posts" },
    },
    { appKey: "blog" }
  );

  customRegistry.setRole("manager", [BlogPerms.posts.create, BlogPerms.posts.edit, BlogPerms.posts.delete, BlogPerms.posts.publish]);

  it("produces the expected effective numeric permission set", () => {
    const { allows, denies } = buildEffectivePermissions({
      roles: ["manager"],
      allows: [BlogPerms.posts.archive],
      denies: [BlogPerms.posts.delete],
      roleRegistry: customRegistry,
    });

    expect(allows).toEqual(
      expect.arrayContaining([
        BlogPerms.posts.create.id,
        BlogPerms.posts.edit.id,
        BlogPerms.posts.publish.id,
        BlogPerms.posts.archive.id,
      ])
    );
    expect(allows).not.toContain(BlogPerms.posts.delete.id);
    expect(denies).toEqual([BlogPerms.posts.delete.id]);
  });
});

describe("intersectPermissions (API token cap)", () => {
  const customRegistry = new RoleRegistry();
  const BlogPerms = definePermissions(
    {
      posts: { create: "Create posts", edit: "Edit posts", delete: "Delete posts" },
      comments: { moderate: "Moderate comments" },
    },
    { appKey: "blog" }
  );

  customRegistry.setRole("editor", [BlogPerms.posts.create, BlogPerms.posts.edit, BlogPerms.comments.moderate]);

  const heldUser = {
    role: "editor",
    overrides: { allows: [], denies: [BlogPerms.posts.edit.id] },
  };

  it("caps requested permissions to effective permissions of owner", () => {
    const result = intersectPermissions(
      heldUser,
      [BlogPerms.posts.create, BlogPerms.posts.edit, BlogPerms.posts.delete],
      customRegistry
    );
    expect(result.allows).toEqual([BlogPerms.posts.create.id]);
    expect(result.denies).toEqual([]);
  });
});
