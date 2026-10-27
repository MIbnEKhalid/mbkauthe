import { describe, it, expect } from "vitest";
import { attachSessionPermissions, hasNoSessionPermissions, SUPERADMIN_SNAPSHOT, checkPermission, checkRolePermission, AuthorizationService, ensureSession, ensureSessionAsync, hasSessionCookie, defineResource, hasAction } from "../../dist/index.js";

const DnsResource = defineResource("dns", {
  view: 1,
  create: 2,
  delete: 8,
});

describe("Authentication & Authorization Speed Optimizations", () => {
  describe("Superadmin Zero-DB Fast Path", () => {
    it("attachSessionPermissions returns immediately with SUPERADMIN_SNAPSHOT when role is superadmin", async () => {
      const sessionUser = { username: "root", role: "superadmin" };
      const result = await attachSessionPermissions(sessionUser, "root", "superadmin");

      expect(result).toBe(SUPERADMIN_SNAPSHOT);
      expect(sessionUser.roles).toEqual(["superadmin"]);
      expect(sessionUser.isSuperadmin).toBe(true);
      expect(sessionUser.perms).toEqual({});
    });

    it("attachSessionPermissions detects superadmin from sessionUser.role if knownRole is omitted", async () => {
      const sessionUser = { username: "admin_user", role: "superadmin" };
      const result = await attachSessionPermissions(sessionUser, "admin_user");

      expect(result).toBe(SUPERADMIN_SNAPSHOT);
      expect(sessionUser.isSuperadmin).toBe(true);
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
        render() { },
      };

      await checkPermission(DnsResource.actions.delete)(req, res, () => {
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
        render() { },
      };

      await checkRolePermission("auditor")(req, res, () => {
        calledNext = true;
      });

      expect(calledNext).toBe(true);
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
        perms: { dns: 1 },
      })).toBe(false);

      expect(hasNoSessionPermissions({
        username: "root",
        roles: ["superadmin"],
        role: "superadmin",
      })).toBe(false);
    });
  });

  describe("AuthorizationService Bitmask Checks", () => {
    it("allows user with matching action mask instantly without DB queries", () => {
      const authService = new AuthorizationService();
      const user = {
        username: "bob",
        role: "normaluser",
        perms: { dns: DnsResource.actions.view.mask },
      };

      expect(authService.hasPermission(user, DnsResource.actions.view)).toBe(true);
      expect(authService.hasPermission(user, DnsResource.actions.delete)).toBe(false);
    });

    it("checks direct bitwise mask", () => {
      const mask = 1 | 2 | 4; // 7
      expect(hasAction(mask, 1)).toBe(true);
      expect(hasAction(mask, 4)).toBe(true);
      expect(hasAction(mask, 8)).toBe(false);
    });
  });

  describe("On-Demand Protected-Routes-Only Session Architecture", () => {
    it("hasSessionCookie detects presence of session cookies accurately", () => {
      expect(hasSessionCookie({ headers: {} })).toBe(false);
      expect(hasSessionCookie({ headers: { cookie: "other=123" } })).toBe(false);
      expect(hasSessionCookie({ headers: { cookie: "mbkauthe.sid=s%3Axyz" } })).toBe(true);
      expect(hasSessionCookie({ headers: { cookie: "session_id=encrypted-uuid" } })).toBe(true);
    });

    it("ensureSession bypasses store initialization when Authorization header is present", () => {
      const req = {
        headers: { authorization: "Bearer mbk_pat_1234567890" },
      };
      let calledNext = false;
      ensureSession(req, {}, () => {
        calledNext = true;
      });
      expect(calledNext).toBe(true);
      expect(req.session).toBeUndefined();
    });

    it("ensureSession immediately calls next() if session is already initialized", () => {
      const req = {
        headers: {},
        session: { user: { username: "existing" } },
      };
      let calledNext = false;
      ensureSession(req, {}, () => {
        calledNext = true;
      });
      expect(calledNext).toBe(true);
    });

    it("ensureSessionAsync resolves immediately if session or Authorization header exists", async () => {
      const reqWithBearer = {
        headers: { authorization: "Bearer mbk_pat_test" },
      };
      await expect(ensureSessionAsync(reqWithBearer, {})).resolves.toBeUndefined();

      const reqWithSession = {
        headers: {},
        session: { user: { username: "bob" } },
      };
      await expect(ensureSessionAsync(reqWithSession, {})).resolves.toBeUndefined();
    });
  });
});
