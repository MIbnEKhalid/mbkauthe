import { describe, test, expect, beforeEach, afterEach } from "vitest";
import { extractRequestOrigin, isLocalOnlyUser, isProductionEnvironment, ErrorCodes, ErrorMessages, mbkautheVar } from "../../dist/index.js";

describe("Origin Extraction and Local-Only User Restrictions", () => {
  describe("extractRequestOrigin", () => {
    test("extracts domain from Origin header", () => {
      const req = {
        headers: {
          origin: "https://portal.mbktech.org/dashboard",
        },
      };
      expect(extractRequestOrigin(req)).toBe("portal.mbktech.org");
    });

    test("extracts domain with custom port from Origin header", () => {
      const req = {
        headers: {
          origin: "http://localhost:5555",
        },
      };
      expect(extractRequestOrigin(req)).toBe("localhost:5555");
    });

    test("falls back to Referer when Origin is missing", () => {
      const req = {
        headers: {
          referer: "https://auth.example.com/mbkauthe/login",
        },
      };
      expect(extractRequestOrigin(req)).toBe("auth.example.com");
    });

    test("extracts domain from x-forwarded-host header", () => {
      const req = {
        headers: {
          "x-forwarded-host": "edge.mbktech.org, proxy.mbktech.org",
        },
      };
      expect(extractRequestOrigin(req)).toBe("edge.mbktech.org");
    });

    test("extracts domain from host header or req.get('host')", () => {
      const reqWithGet = {
        headers: {},
        get: (h) => (h === "host" ? "internal.mbktech.org:8080" : undefined),
      };
      expect(extractRequestOrigin(reqWithGet)).toBe("internal.mbktech.org:8080");

      const reqWithHeaderOnly = {
        headers: { host: "direct.mbktech.org" },
      };
      expect(extractRequestOrigin(reqWithHeaderOnly)).toBe("direct.mbktech.org");
    });

    test("returns Unknown when no origin headers are present", () => {
      const req = { headers: {} };
      expect(extractRequestOrigin(req)).toBe("Unknown");
    });
  });

  describe("isLocalOnlyUser helper", () => {
    test("identifies true boolean and numeric 1 as local-only", () => {
      expect(isLocalOnlyUser(true)).toBe(true);
      expect(isLocalOnlyUser(1)).toBe(true);
      expect(isLocalOnlyUser("1")).toBe(true);
      expect(isLocalOnlyUser("true")).toBe(true);
    });

    test("identifies false, 0, undefined, null as not local-only", () => {
      expect(isLocalOnlyUser(false)).toBe(false);
      expect(isLocalOnlyUser(0)).toBe(false);
      expect(isLocalOnlyUser("0")).toBe(false);
      expect(isLocalOnlyUser("false")).toBe(false);
      expect(isLocalOnlyUser(undefined)).toBe(false);
      expect(isLocalOnlyUser(null)).toBe(false);
    });
  });

  describe("Error Catalog for LOCAL_USER_PROD_RESTRICTED", () => {
    test("error code 606 is mapped in catalog", () => {
      expect(ErrorCodes.LOCAL_USER_PROD_RESTRICTED).toBe(606);
      const detail = ErrorMessages[606];
      expect(detail).toBeDefined();
      expect(detail.userMessage).toContain("restricted to local");
    });
  });

  describe("isProductionEnvironment", () => {
    const originalEnv = process.env.NODE_ENV;
    const originalIsDeployed = mbkautheVar.IS_DEPLOYED;

    afterEach(() => {
      process.env.NODE_ENV = originalEnv;
      mbkautheVar.IS_DEPLOYED = originalIsDeployed;
    });

    test("detects production when NODE_ENV is production", () => {
      process.env.NODE_ENV = "production";
      expect(isProductionEnvironment()).toBe(true);
    });

    test("detects production when IS_DEPLOYED is true", () => {
      process.env.NODE_ENV = "test";
      mbkautheVar.IS_DEPLOYED = "true";
      expect(isProductionEnvironment()).toBe(true);
    });

    test("returns false in dev/test environment", () => {
      process.env.NODE_ENV = "test";
      mbkautheVar.IS_DEPLOYED = "false";
      delete process.env.env;
      expect(isProductionEnvironment()).toBe(false);
    });
  });
});
