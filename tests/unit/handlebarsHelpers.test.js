import { describe, it, expect } from "vitest";
import { authHandlebarsHelpers } from "../../dist/index.js";

describe("MBKAuthe Auth Handlebars Helpers", () => {
  describe("Permission helpers", () => {
    it("superadmin role bypasses permission check in hasPerm", () => {
      const context = { role: "superadmin" };
      expect(authHandlebarsHelpers.hasPerm.call(context, "portal:users:view", {})).toBe(true);
    });

    it("superadmin role bypasses permission check in hasAnyPerm", () => {
      const context = { role: "superadmin" };
      expect(authHandlebarsHelpers.hasAnyPerm.call(context, "portal:fake:perm", {})).toBe(true);
    });

    it("can block helper renders fn for allowed and inverse for denied", () => {
      const opts = { fn: () => "YES", inverse: () => "NO" };
      expect(authHandlebarsHelpers.can.call({ role: "superadmin" }, "portal:test", opts)).toBe("YES");
      expect(authHandlebarsHelpers.can.call({ sessionUser: { role: "guest", permissions: { allows: [], denies: [] } } }, "portal:test", opts)).toBe("NO");
    });

    it("cachebust and acachebust helpers return mbkauthe package version or overridden version", () => {
      expect(authHandlebarsHelpers.cachebust()).toMatch(/^\?v=\d+\.\d+\.\d+/);
      expect(authHandlebarsHelpers.cachebust("9.9.9")).toBe("?v=9.9.9");
      expect(authHandlebarsHelpers.acachebust()).toMatch(/^\?v=\d+\.\d+\.\d+/);
      expect(authHandlebarsHelpers.acachebust("8.8.8")).toBe("?v=8.8.8");
    });
  });
});