import { describe, it, expect } from "vitest";
import { AuthContext, createAuthContext, createAnonymousContext, createSessionAuthContext, createTokenAuthContext, principalFromUser, AuthorizationService, authorizationService, RoleRegistry } from "../../dist/index.js";

describe("AuthContext and Principal Model", () => {
  it("creates an anonymous context with isAuthenticated = false", () => {
    const ctx = createAnonymousContext("blog-app");
    expect(ctx.isAuthenticated).toBe(false);
    expect(ctx.authMethod).toBe("none");
    expect(ctx.principal).toBeNull();
    expect(ctx.username).toBe("");
    expect(ctx.role).toBe("");
    expect(ctx.roles).toEqual([]);
    expect(ctx.appKey).toBe("blog-app");
  });

  it("creates a session-based AuthContext from user object", () => {
    const ctx = createSessionAuthContext(
      {
        user_id: 101,
        username: "alice",
        role: "editor",
        roles: ["writer", "reviewer"],
        allowed_apps: ["blog", "portal"],
      },
      {
        id: "sess-uuid-1234",
        expiresAt: new Date(Date.now() + 3600000),
      }
    );

    expect(ctx.isAuthenticated).toBe(true);
    expect(ctx.authMethod).toBe("session");
    expect(ctx.username).toBe("alice");
    expect(ctx.role).toBe("editor");
    expect(ctx.roles).toEqual(expect.arrayContaining(["editor", "writer", "reviewer"]));
    expect(ctx.session?.id).toBe("sess-uuid-1234");
    // Backwards compatibility getter
    expect(ctx.user?.username).toBe("alice");
  });

  it("creates an API token-based AuthContext", () => {
    const ctx = createTokenAuthContext(
      {
        user_id: 202,
        username: "service-worker",
        role: "service",
        token_permissions: ["api:read", "api:write"],
      },
      {
        id: "tok-999",
        name: "CLI Token",
      }
    );

    expect(ctx.isAuthenticated).toBe(true);
    expect(ctx.authMethod).toBe("api-token");
    expect(ctx.username).toBe("service-worker");
    expect(ctx.token?.id).toBe("tok-999");
    expect(ctx.type).toBe("api-token");
  });

  it("normalizes user variations cleanly with principalFromUser", () => {
    const p1 = principalFromUser({ username: "bob", role: "ADMIN", user_allowed_apps: ["APP1"] });
    expect(p1.username).toBe("bob");
    expect(p1.role).toBe("ADMIN");
    expect(p1.allowed_apps).toEqual(["app1"]);

    const p2 = principalFromUser(null);
    expect(p2.username).toBe("");
    expect(p2.role).toBe("guest");
    expect(p2.is_active).toBe(false);
  });

  it("supports immutability and with() cloning", () => {
    const original = createSessionAuthContext({ username: "alice", role: "member" });
    const cloned = original.with({ appKey: "my-app", attributes: { tenantId: "tenant-42" } });

    expect(original.appKey).toBeNull();
    expect(cloned.appKey).toBe("my-app");
    expect(cloned.attributes.tenantId).toBe("tenant-42");
    expect(cloned.username).toBe("alice");
  });
});

describe("AuthorizationService — Pure Authorization Decisions", () => {
  const customRegistry = new RoleRegistry();
  customRegistry.setRole("editor", ["blog:posts:create", "blog:posts:edit", "blog:posts:view"]);
  customRegistry.setRole("admin", ["blog:*:*"]);
  const authz = new AuthorizationService(customRegistry);

  describe("Role checks", () => {
    it("recognizes superadmin role and case-insensitivity", () => {
      const superUser = createSessionAuthContext({ username: "root", role: "SuperAdmin" });
      expect(authz.isSuperadmin(superUser)).toBe(true);
      expect(authz.hasRole(superUser, "any_role")).toBe(true);
      expect(authz.hasAnyRole(superUser, ["manager", "billing"])).toBe(true);
    });

    it("evaluates hasRole and hasAnyRole on normal users", () => {
      const editorCtx = createSessionAuthContext({ username: "ed", role: "editor", roles: ["moderator"] });
      expect(authz.hasRole(editorCtx, "editor")).toBe(true);
      expect(authz.hasRole(editorCtx, "moderator")).toBe(true);
      expect(authz.hasRole(editorCtx, "admin")).toBe(false);
      expect(authz.hasAnyRole(editorCtx, ["admin", "editor"])).toBe(true);
      expect(authz.hasAnyRole(editorCtx, "any")).toBe(true);
    });

    it("evaluates isRoleDenied accurately", () => {
      const guestCtx = createSessionAuthContext({ username: "guest_user", role: "guest" });
      expect(authz.isRoleDenied(guestCtx, "guest")).toBe(true);
      expect(authz.isRoleDenied(guestCtx, "admin")).toBe(false);
    });
  });

  describe("Permission checks with wildcards and overrides", () => {
    it("allows permissions defined in role registry", () => {
      const user = createSessionAuthContext({ username: "alice", role: "editor" });
      expect(authz.hasPermission(user, "blog:posts:create")).toBe(true);
      expect(authz.hasPermission(user, "blog:posts:delete")).toBe(false);
    });

    it("evaluates wildcard permissions", () => {
      const adminUser = createSessionAuthContext({ username: "charlie", role: "admin" });
      expect(authz.hasPermission(adminUser, "blog:posts:delete")).toBe(true);
      expect(authz.hasPermission(adminUser, "blog:comments:ban")).toBe(true);
      expect(authz.hasPermission(adminUser, "other:app:action")).toBe(false);
    });

    it("enforces deny overrides strictly (deny always wins)", () => {
      const editorWithDeny = createSessionAuthContext({
        username: "alice",
        role: "editor",
        overrides: {
          allows: ["blog:posts:delete"],
          denies: ["blog:posts:edit", "blog:posts:delete"],
        },
      });

      // Role gives blog:posts:create -> allowed
      expect(authz.hasPermission(editorWithDeny, "blog:posts:create")).toBe(true);
      // Deny blocks blog:posts:edit despite role -> denied
      expect(authz.hasPermission(editorWithDeny, "blog:posts:edit")).toBe(false);
      // Deny blocks blog:posts:delete despite allow override -> denied
      expect(authz.hasPermission(editorWithDeny, "blog:posts:delete")).toBe(false);
    });

    it("allows exceptional permissions via allow override", () => {
      const editorWithAllow = createSessionAuthContext({
        username: "alice",
        role: "editor",
        overrides: {
          allows: ["billing:invoices:view"],
          denies: [],
        },
      });

      expect(authz.hasPermission(editorWithAllow, "billing:invoices:view")).toBe(true);
    });

    it("evaluates hasAllPermissions and hasAnyPermission", () => {
      const user = createSessionAuthContext({ username: "alice", role: "editor" });
      expect(authz.hasAllPermissions(user, ["blog:posts:create", "blog:posts:edit"])).toBe(true);
      expect(authz.hasAllPermissions(user, ["blog:posts:create", "blog:posts:delete"])).toBe(false);
      expect(authz.hasAnyPermission(user, ["billing:invoices:view", "blog:posts:create"])).toBe(true);
      expect(authz.hasAnyPermission(user, ["billing:a", "billing:b"])).toBe(false);
    });
  });

  describe("Application access checks", () => {
    it("allows superadmin to access any application", () => {
      const superUser = createSessionAuthContext({ username: "root", role: "superadmin", allowed_apps: [] });
      expect(authz.canAccessApp(superUser, "any-app")).toBe(true);
      expect(authz.canAccessApp(superUser, "internal-tools")).toBe(true);
    });

    it("enforces allowed_apps list for normal users case-insensitively", () => {
      const user = createSessionAuthContext({
        username: "dave",
        role: "normaluser",
        allowed_apps: ["mbkauthe", "Dashboard", "Blog"],
      });

      expect(authz.canAccessApp(user, "mbkauthe")).toBe(true);
      expect(authz.canAccessApp(user, "dashboard")).toBe(true);
      expect(authz.canAccessApp(user, "BLOG")).toBe(true);
      expect(authz.canAccessApp(user, "secret-finance-portal")).toBe(false);
    });
  });

  describe("Policy Evaluation", () => {
    it("evaluates custom policy functions against AuthContext", async () => {
      const user = createSessionAuthContext({
        username: "eve",
        role: "analyst",
      });

      const isAnalystPolicy = (ctx) => ctx.role === "analyst";
      const isSuperadminPolicy = (ctx) => ctx.role === "superadmin";

      expect(await authz.evaluatePolicy(user, isAnalystPolicy)).toBe(true);
      expect(await authz.evaluatePolicy(user, isSuperadminPolicy)).toBe(false);
    });
  });
});
