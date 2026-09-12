import { describe, it, expect } from "vitest";
import { commonHandlebarsHelpers, handlebarsHelpers } from "../../lib/utils/handlebarsHelpers.js";

describe("MBKAuthe Shared Handlebars Helpers", () => {
  it("exports commonHandlebarsHelpers and handlebarsHelpers as equivalent", () => {
    expect(commonHandlebarsHelpers).toBe(handlebarsHelpers);
  });

  describe("Permission helpers", () => {
    it("superadmin role bypasses permission check in hasPerm", () => {
      const context = { role: "superadmin" };
      expect(handlebarsHelpers.hasPerm.call(context, "portal:users:view", {})).toBe(true);
    });

    it("superadmin role bypasses permission check in hasAnyPerm", () => {
      const context = { role: "superadmin" };
      expect(handlebarsHelpers.hasAnyPerm.call(context, "portal:fake:perm", {})).toBe(true);
    });

    it("can block helper renders fn for allowed and inverse for denied", () => {
      const opts = { fn: () => "YES", inverse: () => "NO" };
      expect(handlebarsHelpers.can.call({ role: "superadmin" }, "portal:test", opts)).toBe("YES");
      expect(handlebarsHelpers.can.call({ sessionUser: { role: "guest", permissions: { allows: [], denies: [] } } }, "portal:test", opts)).toBe("NO");
    });
  });

  describe("Comparisons and Logic", () => {
    it("eq and neq work correctly", () => {
      expect(handlebarsHelpers.eq(5, 5)).toBe(true);
      expect(handlebarsHelpers.eq("5", 5)).toBe(true);
      expect(handlebarsHelpers.neq(5, 6)).toBe(true);
    });

    it("and / or / not work correctly", () => {
      expect(handlebarsHelpers.and(true, true, {})).toBe(true);
      expect(handlebarsHelpers.and(true, false, {})).toBe(false);
      expect(handlebarsHelpers.or(false, true, {})).toBe(true);
      expect(handlebarsHelpers.not(true)).toBe(false);
      expect(handlebarsHelpers.not(false)).toBe(true);
    });

    it("numeric comparisons gt, gte, lt, lte work", () => {
      expect(handlebarsHelpers.gt(10, 5)).toBe(true);
      expect(handlebarsHelpers.gte(10, 10)).toBe(true);
      expect(handlebarsHelpers.lt(5, 10)).toBe(true);
      expect(handlebarsHelpers.lte(5, 5)).toBe(true);
    });

    it("ifCond handles various operators", () => {
      const opts = { fn: () => "OK", inverse: () => "FAIL" };
      expect(handlebarsHelpers.ifCond(10, ">", 5, opts)).toBe("OK");
      expect(handlebarsHelpers.ifCond(10, "<=", 5, opts)).toBe("FAIL");
      expect(handlebarsHelpers.ifCond(10, "==", "10", opts)).toBe("OK");
      expect(handlebarsHelpers.ifCond(10, "===", "10", opts)).toBe("FAIL");
    });
  });

  describe("Formatting and Utilities", () => {
    it("formatNumber formats k, M, B correctly", () => {
      expect(handlebarsHelpers.formatNumber(500)).toBe("500");
      expect(handlebarsHelpers.formatNumber(1500)).toBe("1.5k");
      expect(handlebarsHelpers.formatNumber(2000000)).toBe("2M");
      expect(handlebarsHelpers.formatNumber(3000000000)).toBe("3B");
    });

    it("formatBytes formats byte sizes", () => {
      expect(handlebarsHelpers.formatBytes(0)).toBe("0 Bytes");
      expect(handlebarsHelpers.formatBytes(1024)).toBe("1 KB");
      expect(handlebarsHelpers.formatBytes(1048576)).toBe("1 MB");
    });

    it("getInitials extracts 2 initials", () => {
      expect(handlebarsHelpers.getInitials("john.doe")).toBe("JD");
      expect(handlebarsHelpers.getInitials("admin")).toBe("A");
      expect(handlebarsHelpers.getInitials("")).toBe("?");
    });

    it("truncate and truncateUrl work properly", () => {
      expect(handlebarsHelpers.truncate("Hello World", 5)).toBe("Hello...");
      expect(handlebarsHelpers.truncateUrl("https://example.com/very/long/path/to/resource", 20)).toContain("...");
    });

    it("slug converts strings to kebab-case", () => {
      expect(handlebarsHelpers.slug("In Progress")).toBe("in-progress");
      expect(handlebarsHelpers.slug("User Settings Page")).toBe("user-settings-page");
    });

    it("range creates valid number arrays", () => {
      expect(handlebarsHelpers.range(1, 5)).toEqual([1, 2, 3, 4, 5]);
    });
  });
});
