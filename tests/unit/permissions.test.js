// Pure permission core — no database required.

// config is read lazily; set an APP_NAME so `definePermissions` can auto-prefix.
process.env.APP_NAME = process.env.APP_NAME || "testblog";

const {
  definePermissions,
  hasPermission,
  permissionMatches,
  normalizePermissions,
  buildEffectivePermissions,
  collectPermissions,
  intersectPermissions,
  defineGlobalPermissions,
  GlobalPermissions,
  resolvePermission,
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

  it("falls back to configured app key when appKey option is blank", () => {
    const Permissions = definePermissions({ posts: { delete: "Delete" } }, { appKey: "" });
    const app = (process.env.APP_NAME || "").toLowerCase();
    expect(Permissions.posts.delete).toBe(`${app}:posts:delete`);
  });

  it("lowercases service/action keys", () => {
    const Permissions = definePermissions({ Posts: { Delete: "Delete" } }, { appKey: "blog" });
    expect(Permissions.posts.delete).toBe("blog:posts:delete");
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
    const user = { role: "superadmin", permissions: { allows: [], denies: [] } };
    expect(hasPermission(user, "blog:posts:delete")).toBe(true);
  });

  it("returns true for SUPERADMIN (case-insensitive role)", () => {
    expect(hasPermission({ role: "SuperAdmin", permissions: [] }, "x:y:z")).toBe(true);
  });
});

describe("hasPermission — allow/deny basics", () => {
  const allowedUser = { role: "editor", permissions: ["blog:posts:create", "blog:posts:delete"] };

  it("allows when permission present (plain array form)", () => {
    expect(hasPermission(allowedUser, "blog:posts:delete")).toBe(true);
  });

  it("denies an unknown permission", () => {
    expect(hasPermission(allowedUser, "blog:posts:archive")).toBe(false);
  });

  it("denies empty permissions", () => {
    expect(hasPermission({ role: "editor", permissions: [] }, "blog:posts:create")).toBe(false);
    expect(hasPermission({ role: "editor", permissions: { allows: [], denies: [] } }, "blog:posts:create")).toBe(false);
  });

  it("denies when user has no permissions field", () => {
    expect(hasPermission({ role: "editor" }, "blog:posts:create")).toBe(false);
  });

  it("denies when user is null/undefined", () => {
    expect(hasPermission(null, "blog:posts:create")).toBe(false);
    expect(hasPermission(undefined, "blog:posts:create")).toBe(false);
  });

  it("treats object-form permissions as allow list with denies", () => {
    const user = { role: "editor", permissions: { allows: ["blog:posts:create"], denies: [] } };
    expect(hasPermission(user, "blog:posts:create")).toBe(true);
  });
});

describe("hasPermission — deny always wins", () => {
  it("deny beats allow override for the same permission", () => {
    const user = { role: "editor", permissions: { allows: ["blog:posts:delete"], denies: ["blog:posts:delete"] } };
    expect(hasPermission(user, "blog:posts:delete")).toBe(false);
  });

  it("deny wins even when a matching allow also exists", () => {
    const user = { role: "editor", permissions: { allows: ["*:posts:delete"], denies: ["blog:posts:delete"] } };
    expect(hasPermission(user, "blog:posts:delete")).toBe(false);
  });
});

describe("hasPermission — wildcard matching", () => {
  const wildcardUser = { role: "editor", permissions: ["blog:*:read", "*:posts:delete", "*:*:view"] };

  it("matches wildcard service", () => {
    expect(hasPermission(wildcardUser, "blog:comments:read")).toBe(true);
    expect(hasPermission(wildcardUser, "blog:anything:read")).toBe(true);
  });

  it("matches wildcard app", () => {
    expect(hasPermission(wildcardUser, "other:posts:delete")).toBe(true);
  });

  it("matches wildcard action", () => {
    expect(hasPermission(wildcardUser, "anything:posts:view")).toBe(true);
  });

  it("wildcard in required matches concrete stored permission", () => {
    const user = { role: "editor", permissions: ["blog:posts:delete"] };
    expect(hasPermission(user, "blog:*:delete")).toBe(true);
    expect(hasPermission(user, "*:posts:delete")).toBe(true);
    expect(hasPermission(user, "*:*:delete")).toBe(true);
  });

  it("does not over-match across segments", () => {
    const user = { role: "editor", permissions: ["blog:posts:read"] };
    expect(hasPermission(user, "blog:posts:delete")).toBe(false);
    expect(hasPermission(user, "blog:comments:read")).toBe(false);
    expect(hasPermission(user, "other:posts:read")).toBe(false);
  });
});

describe("permissionMatches", () => {
  it("matches exact triples", () => {
    expect(permissionMatches("blog:posts:delete", "blog:posts:delete")).toBe(true);
    expect(permissionMatches("blog:posts:delete", "blog:posts:create")).toBe(false);
  });
  it("is wildcard aware on both sides", () => {
    expect(permissionMatches("*:posts:delete", "blog:posts:delete")).toBe(true);
    expect(permissionMatches("blog:posts:*", "blog:posts:delete")).toBe(true);
    expect(permissionMatches("blog:posts:delete", "*:*:*")).toBe(true);
  });
  it("handles malformed strings", () => {
    expect(permissionMatches("", "blog:posts:delete")).toBe(false);
    expect(permissionMatches("blog:posts", "blog:posts:delete")).toBe(false);
    expect(permissionMatches(null, "blog:posts:delete")).toBe(false);
  });
});

describe("normalizePermissions", () => {
  it("coerces arrays to allows with empty denies", () => {
    expect(normalizePermissions(["A:B:C", "X:Y:Z"])).toEqual({ allows: ["a:b:c", "x:y:z"], denies: [] });
  });
  it("passes through object form", () => {
    expect(normalizePermissions({ allows: ["A:B:C"], denies: ["D:E:F"] })).toEqual({
      allows: ["a:b:c"],
      denies: ["d:e:f"],
    });
  });
  it("handles null/undefined/string", () => {
    expect(normalizePermissions(null)).toEqual({ allows: [], denies: [] });
    expect(normalizePermissions(undefined)).toEqual({ allows: [], denies: [] });
    expect(normalizePermissions("A:B:C")).toEqual({ allows: ["a:b:c"], denies: [] });
  });
});

describe("buildEffectivePermissions — role/template inheritance", () => {
  const Manager = ["blog:posts:create", "blog:posts:edit", "blog:posts:delete", "blog:posts:publish"];
  const Editor = ["blog:posts:edit", "blog:posts:publish", "blog:comments:moderate"];

  it("inherits a single template", () => {
    const { allows } = buildEffectivePermissions({ templates: [Manager] });
    expect(allows).toContain("blog:posts:create");
    expect(allows).toContain("blog:posts:publish");
  });

  it("unions multiple templates", () => {
    const { allows } = buildEffectivePermissions({ templates: [Manager, Editor] });
    expect(allows).toEqual(expect.arrayContaining(["blog:posts:create", "blog:posts:edit", "blog:posts:delete", "blog:posts:publish", "blog:comments:moderate"]));
  });

  it("applies user deny override (removes inherited permission)", () => {
    const { allows, denies } = buildEffectivePermissions({ templates: [Manager], denies: ["blog:posts:delete"] });
    expect(allows).not.toContain("blog:posts:delete");
    expect(allows).toContain("blog:posts:create");
    expect(denies).toContain("blog:posts:delete");
  });

  it("applies user allow override (grants otherwise-uninherited permission)", () => {
    const { allows } = buildEffectivePermissions({ templates: [Manager], allows: ["blog:posts:archive"] });
    expect(allows).toContain("blog:posts:archive");
  });

  it("deny always wins over allow override", () => {
    const { allows } = buildEffectivePermissions({
      templates: [Manager],
      allows: ["blog:posts:delete"],
      denies: ["blog:posts:delete"],
    });
    expect(allows).not.toContain("blog:posts:delete");
  });

  it("produces the spec example (Manager + DENY delete + ALLOW archive)", () => {
    const { allows } = buildEffectivePermissions({
      templates: [["blog:posts:create", "blog:posts:edit", "blog:posts:delete", "blog:posts:publish"]],
      allows: ["blog:posts:archive"],
      denies: ["blog:posts:delete"],
    });
    expect(allows).toEqual(
      expect.arrayContaining(["blog:posts:create", "blog:posts:edit", "blog:posts:publish", "blog:posts:archive"])
    );
    expect(allows).not.toContain("blog:posts:delete");
  });

  it("handles no input", () => {
    expect(buildEffectivePermissions({})).toEqual({ allows: [], denies: [] });
  });
});

describe("intersectPermissions (API token cap)", () => {
  const held = { allows: ["blog:posts:create", "blog:posts:edit", "blog:comments:moderate"], denies: [] };

  it("keeps only requested permissions the owner holds", () => {
    const result = intersectPermissions(held, ["blog:posts:create", "blog:posts:delete"]);
    expect(result.allows).toEqual(["blog:posts:create"]);
    expect(result.denies).toEqual([]);
  });

  it("honours wildcard grants on the owner side", () => {
    const result = intersectPermissions({ allows: ["blog:posts:*"], denies: [] }, ["blog:posts:delete"]);
    expect(result.allows).toEqual(["blog:posts:delete"]);
  });

  it("an owner deny always wins", () => {
    const result = intersectPermissions(
      { allows: ["blog:posts:delete"], denies: ["blog:posts:delete"] },
      ["blog:posts:delete"]
    );
    expect(result.allows).toEqual([]);
  });

  it("accepts a plain string allow list", () => {
    const result = intersectPermissions(["blog:posts:create"], ["blog:posts:create"]);
    expect(result.allows).toEqual(["blog:posts:create"]);
  });

  it("returns nothing when the owner holds nothing", () => {
    expect(intersectPermissions({ allows: [], denies: [] }, ["blog:posts:create"])).toEqual({ allows: [], denies: [] });
  });

  it("normalizes and de-duplicates the requested list", () => {
    const result = intersectPermissions(held, [" BLOG:Posts:Create ", "blog:posts:create"]);
    expect(result.allows).toEqual(["blog:posts:create"]);
  });
});
