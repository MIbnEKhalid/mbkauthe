import { describe, test, expect } from "vitest";
import { validateLoginDto, validateTotpDto, validateCreateApiTokenDto, validateCliDeviceCodeDto, MbkAuthError } from "../../dist/index.js";

describe("DTO Validation Layer", () => {
  test("validates and trims login credentials", () => {
    const res = validateLoginDto({ username: "  alice  ", password: "mypassword", rememberMe: true });
    expect(res.username).toBe("alice");
    expect(res.password).toBe("mypassword");
    expect(res.rememberMe).toBe(true);
  });

  test("throws MbkAuthError on missing login fields", () => {
    expect(() => validateLoginDto({ username: "", password: "pwd" })).toThrow(MbkAuthError);
    expect(() => validateLoginDto({ username: "alice", password: "" })).toThrow(MbkAuthError);
    expect(() => validateLoginDto(null)).toThrow(MbkAuthError);
  });

  test("validates TOTP 6-8 digit code", () => {
    const res = validateTotpDto({ token: " 123 456 ", rememberDevice: true });
    expect(res.token).toBe("123456");
    expect(res.rememberDevice).toBe(true);

    expect(() => validateTotpDto({ token: "123" })).toThrow(MbkAuthError);
    expect(() => validateTotpDto({ token: "abcdef" })).toThrow(MbkAuthError);
  });

  test("validates create API token DTO", () => {
    const res = validateCreateApiTokenDto({
      name: "Deploy Key",
      scopes: ["portal:read", "portal:write"],
      expiresInDays: 30,
    });
    expect(res.name).toBe("Deploy Key");
    expect(res.scopes).toEqual(["portal:read", "portal:write"]);
    expect(res.expiresInDays).toBe(30);

    const fromComma = validateCreateApiTokenDto({
      name: "CLI Key",
      scopes: "portal:read, portal:write",
    });
    expect(fromComma.scopes).toEqual(["portal:read", "portal:write"]);
  });

  test("validates CLI device code DTO", () => {
    const res = validateCliDeviceCodeDto({ device_code: "dev_123" });
    expect(res.deviceCode).toBe("dev_123");

    expect(() => validateCliDeviceCodeDto({})).toThrow(MbkAuthError);
  });
});
