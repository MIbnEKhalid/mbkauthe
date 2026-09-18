import { describe, it, expect } from "vitest";
import {
  attachSessionPermissions,
  hasNoSessionPermissions,
  SUPERADMIN_PERMISSIONS,
  checkPermission,
  checkRolePermission,
  permissionMatches,
  AuthorizationService,
  defaultRoleRegistry,
  RoleRegistry,
} from "../../dist/index.js";

describe("Authentication & Authorization Speed Optimizations", () => {
  describe("Superadmin Zero-DB Fast Path", () => {
    it("attachSessionPermissions returns immediately with SUPERADMIN_PERMISSIONS when role is superadmin", async () => {
      const sessionUser = { username: "root", role: "superadmin" };
      const result = await attachSessionPermissions(sessionUser, "root", "superadmin");

      expect(result).toBe(SUPERADMIN_PERMISSIONS);
      expect(sessionUser.roles).toEqual(["superadmin"]);
      expect(sessionUser.permissions).toEqual({ allows: ["*"], denies: [] });
      expect(sessionUser.overrides).toEqual({ allows: ["*"], denies: [] });
    });

    it("attachSessionPermissions detects superadmin from sessionUser.role if knownRole is omitted", async () => {
      const sessionUser = { username: "admin_user", role: "superadmin" };
      const result = await attachSessionPermissions(sessionUser, "admin_user");

      expect(result).toBe(SUPERADMIN_PERMISSIONS);
      expect(sessionUser.permissions).toEqual({ allows: ["*"], denies: [] });
    });

    it("checkPermission bypasses immediately for superadmin without DB role loading", async () => {
      const req = {
        originalUrl: "/api/protected-resource",
        session: { user: { username: "superadmin", role: "superadmin" } },
        headers: { accept: "application/json" },
      };

      let calledNext = false;
      const res = {
        statusCode: null,
        status(code) { this.statusCode = code; return this; },
        json(p) { return p; },
        render() {},
      };

      await checkPermission("any:strictly:restricted:perm")(req, res, () => {
        calledNext = true;
      });

      expect(calledNext).toBe(true);
      expect(res.statusCode).toBeNull();
    });

    it("checkRolePermission bypasses immediately for superadmin", async () => {
      const req = {
        originalUrl: "/api/roles-only",
        session: { user: { username: "superadmin", role: "superadmin" } },
        headers: { accept: "application/json" },
      };

      let calledNext = false;
      const res = {
        statusCode: null,
        status(code) { this.statusCode = code; return this; },
        json(p) { return p; },
        render() {},
      };

      await checkRolePermission("auditor")(req, res, () => {
        calledNext = true;
      });

      expect(calledNext).toBe(true);
    });
  });

  describe("Fast-path Permission Matching", () => {
    it("exact match succeeds without splitting segments", () => {
      expect(permissionMatches("portal:dns:view", "portal:dns:view")).toBe(true);
      expect(permissionMatches("global:basic:access", "global:basic:access")).toBe(true);
    });

    it("non-wildcard mismatch fails instantly via fast path", () => {
      expect(permissionMatches("portal:dns:view", "portal:dns:delete")).toBe(false);
      expect(permissionMatches("blog:posts:create", "blog:posts:edit")).toBe(false);
    });

    it("wildcard match works correctly", () => {
      expect(permissionMatches("portal:dns:*", "portal:dns:view")).toBe(true);
      expect(permissionMatches("portal:*:*", "portal:dns:view")).toBe(true);
      expect(permissionMatches("*", "portal:dns:view")).toBe(true);
      expect(permissionMatches("*:*:*", "portal:dns:view")).toBe(true);
      expect(permissionMatches("portal:dns:*", "other:dns:view")).toBe(false);
    });
  });

  describe("Session Permission Hydration Check", () => {
    it("hasNoSessionPermissions correctly identifies empty vs populated session users", () => {
      expect(hasNoSessionPermissions(null)).toBe(true);
      expect(hasNoSessionPermissions({})).toBe(true);
      expect(hasNoSessionPermissions({ username: "alice" })).toBe(true);

      expect(hasNoSessionPermissions({
        username: "alice",
        roles: ["normaluser"],
        permissions: { allows: ["portal:dns:view"], denies: [] },
      })).toBe(false);

      expect(hasNoSessionPermissions({
        username: "root",
        roles: ["superadmin"],
        permissions: { allows: ["*"], denies: [] },
      })).toBe(false);
    });
  });

  describe("AuthorizationService Permission Checks", () => {
    it("allows user with matching allow override / effective permission without querying registry", () => {
      const authService = new AuthorizationService();
      const user = {
        username: "bob",
        role: "normaluser",
        permissions: { allows: ["app:reports:view"], denies: [] },
      };

      expect(authService.hasPermission(user, "app:reports:view")).toBe(true);
      expect(authService.hasPermission(user, "app:reports:delete")).toBe(false);
    });

    it("denies user when deny override is present even if role grants it", () => {
      const registry = new RoleRegistry();
      registry.setRole("editor", ["blog:posts:delete"]);
      const authService = new AuthorizationService(registry);

      const user = {
        username: "charlie",
        role: "editor",
        permissions: { allows: ["blog:posts:delete"], denies: ["blog:posts:delete"] },
      };

      expect(authService.hasPermission(user, "blog:posts:delete", registry)).toBe(false);
    });
  });
});
