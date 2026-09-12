// Pure permission core — no database required.

process.env.APP_NAME = process.env.APP_NAME || "testblog";

const {
  definePermissions,
  hasPermission,
  permissionMatches,
  normalizePermissions,
  buildEffectivePermissions,
  collectPermissions,
  collectRoles,
  intersectPermissions,
  defineGlobalPermissions,
  GlobalPermissions,
  resolvePermission,
  RoleRegistry,
  defaultRoleRegistry,
} = await import("../../lib/permissions.js");

describe("definePermissions", () => {
  it("resolves nested service/action access to app:service:action strings", () => {
    const Permissions = definePermissions(
      {
        posts: { create: "Create posts", edit: "Edit posts", delete: "Delete posts" },
        comments: { moderate: "Moderate comments" },
      },
      { appKey: "blog" }
    );

    expect(Permissions.posts.create).toBe("blog:posts:create");
    expect(Permissions.posts.edit).toBe("blog:posts:edit");
    expect(Permissions.posts.delete).toBe("blog:posts:delete");
    expect(Permissions.comments.moderate).toBe("blog:comments:moderate");
  });

  it("auto-prefixes with the configured app key (mbkautheVar.APP_NAME)", () => {
    const Permissions = definePermissions({ posts: { delete: "Delete posts" } });
    const app = (process.env.APP_NAME || "").toLowerCase();
    expect(Permissions.posts.delete).toBe(`${app}:posts:delete`);
  });

  it("collects all declared permissions with labels", () => {
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
      permission: "blog:posts:create",
      label: "Create posts",
    });
  });

  it("collects declared roles from manifest", () => {
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
    expect(roles.find((r) => r.name === "admin").permissions).toEqual(["blog:*:*"]);
    expect(roles.find((r) => r.name === "editor").permissions).toEqual(["blog:posts:create", "blog:posts:edit"]);
  });
});

describe("global permissions", () => {
  it("uses the reserved global namespace for every app", () => {
    const Permissions = defineGlobalPermissions({ pages: { view: "View pages" } });
    expect(Permissions.pages.view).toBe("global:pages:view");
    expect(GlobalPermissions.basic.access).toBe("global:basic:access");
  });

  it("resolves basic.access shorthand to the global namespace", () => {
    expect(resolvePermission("basic.access")).toBe("global:basic:access");
    expect(resolvePermission("portal:dns:view")).toBe("portal:dns:view");
  });
});

describe("hasPermission — SuperAdmin bypass", () => {
  it("returns true for superadmin with no stored permissions", () => {
    const user = { role: "superadmin" };
    expect(hasPermission(user, "blog:posts:delete")).toBe(true);
  });

  it("returns true for superadmin even with an empty permission set", () => {
    const user = { role: "superadmin", overrides: { allows: [], denies: [] } };
    expect(hasPermission(user, "blog:posts:delete")).toBe(true);
  });

  it("returns true for SUPERADMIN in user.roles", () => {
    expect(hasPermission({ role: "member", roles: ["SuperAdmin"] }, "x:y:z")).toBe(true);
  });
});

describe("hasPermission — RoleRegistry & unified roles", () => {
  const customRegistry = new RoleRegistry();
  customRegistry.setRole("editor", ["blog:posts:create", "blog:posts:edit", "blog:comments:moderate"]);
  customRegistry.setRole("viewer", ["blog:posts:view"]);

  it("allows when user's role grants permission", () => {
    const user = { role: "editor" };
    expect(hasPermission(user, "blog:posts:create", customRegistry)).toBe(true);
    expect(hasPermission(user, "blog:posts:edit", customRegistry)).toBe(true);
  });

  it("denies when user's role lacks permission", () => {
    const user = { role: "editor" };
    expect(hasPermission(user, "blog:posts:delete", customRegistry)).toBe(false);
  });

  it("unions multiple roles in user.roles", () => {
    const user = { role: "viewer", roles: ["editor"] };
    expect(hasPermission(user, "blog:posts:view", customRegistry)).toBe(true);
    expect(hasPermission(user, "blog:posts:create", customRegistry)).toBe(true);
  });
});

describe("hasPermission — allow & deny overrides", () => {
  const customRegistry = new RoleRegistry();
  customRegistry.setRole("editor", ["blog:posts:create", "blog:posts:edit", "blog:posts:delete"]);

  it("applies deny override to remove role-granted permission", () => {
    const user = {
      role: "editor",
      overrides: {
        denies: ["blog:posts:delete"],
        allows: [],
      },
    };
    expect(hasPermission(user, "blog:posts:create", customRegistry)).toBe(true);
    expect(hasPermission(user, "blog:posts:delete", customRegistry)).toBe(false);
  });

  it("applies allow override to grant exceptional permission", () => {
    const user = {
      role: "editor",
      overrides: {
        allows: ["blog:posts:publish"],
        denies: [],
      },
    };
    expect(hasPermission(user, "blog:posts:publish", customRegistry)).toBe(true);
  });

  it("deny always wins over allow override", () => {
    const user = {
      role: "editor",
      overrides: {
        allows: ["blog:posts:delete"],
        denies: ["blog:posts:delete"],
      },
    };
    expect(hasPermission(user, "blog:posts:delete", customRegistry)).toBe(false);
  });
});

describe("hasPermission — wildcard matching", () => {
  const customRegistry = new RoleRegistry();
  customRegistry.setRole("admin", ["blog:*:*"]);

  it("matches wildcard permissions from role", () => {
    const user = { role: "admin" };
    expect(hasPermission(user, "blog:posts:create", customRegistry)).toBe(true);
    expect(hasPermission(user, "blog:comments:delete", customRegistry)).toBe(true);
    expect(hasPermission(user, "other:posts:create", customRegistry)).toBe(false);
  });

  it("wildcard deny override blocks everything matching", () => {
    const user = {
      role: "admin",
      overrides: {
        denies: ["blog:comments:*"],
      },
    };
    expect(hasPermission(user, "blog:posts:create", customRegistry)).toBe(true);
    expect(hasPermission(user, "blog:comments:moderate", customRegistry)).toBe(false);
  });
});

describe("buildEffectivePermissions", () => {
  const customRegistry = new RoleRegistry();
  customRegistry.setRole("manager", ["blog:posts:create", "blog:posts:edit", "blog:posts:delete", "blog:posts:publish"]);

  it("produces the expected effective permission set", () => {
    const { allows, denies } = buildEffectivePermissions({
      roles: ["manager"],
      allows: ["blog:posts:archive"],
      denies: ["blog:posts:delete"],
      roleRegistry: customRegistry,
    });

    expect(allows).toEqual(
      expect.arrayContaining(["blog:posts:create", "blog:posts:edit", "blog:posts:publish", "blog:posts:archive"])
    );
    expect(allows).not.toContain("blog:posts:delete");
    expect(denies).toEqual(["blog:posts:delete"]);
  });
});

describe("intersectPermissions (API token cap)", () => {
  const customRegistry = new RoleRegistry();
  customRegistry.setRole("editor", ["blog:posts:create", "blog:posts:edit", "blog:comments:moderate"]);

  const heldUser = {
    role: "editor",
    overrides: { allows: [], denies: ["blog:posts:edit"] },
  };

  it("caps requested permissions to effective permissions of owner", () => {
    const result = intersectPermissions(heldUser, ["blog:posts:create", "blog:posts:edit", "blog:posts:delete"], customRegistry);
    expect(result.allows).toEqual(["blog:posts:create"]);
    expect(result.denies).toEqual([]);
  });
});
