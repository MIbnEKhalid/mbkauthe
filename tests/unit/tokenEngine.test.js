import { describe, test, expect } from "vitest";
import { TokenEngine } from "../../dist/index.js";

describe("Unified Token Engine", () => {
  test("generates prefixed tokens with expected prefixes", () => {
    const pat = TokenEngine.createApiToken();
    expect(pat.startsWith("mbk_pat_")).toBe(true);
    expect(pat.length).toBeGreaterThan(20);

    const cli = TokenEngine.createCliToken();
    expect(cli.startsWith("mbk_cli_")).toBe(true);
  });

  test("hashes tokens predictably with sha256", () => {
    const token = "mbk_pat_1234567890abcdef";
    const hash = TokenEngine.hashToken(token);
    expect(hash).toBeDefined();
    expect(typeof hash).toBe("string");
    expect(hash).toBe(TokenEngine.hashToken(token));
  });

  test("verifies tokens with constant-time check", () => {
    const token = "mbk_pat_secret_value";
    const hash = TokenEngine.hashToken(token);

    expect(TokenEngine.verifyToken(token, hash)).toBe(true);
    expect(TokenEngine.verifyToken("wrong_token", hash)).toBe(false);
    expect(TokenEngine.verifyToken(null, hash)).toBe(false);
  });

  test("parses token prefix and identifies token type", () => {
    const parsedPat = TokenEngine.parseToken("mbk_pat_abcdef123456");
    expect(parsedPat.type).toBe("pat");
    expect(parsedPat.prefix).toBe("mbk_pat_");
    expect(parsedPat.entropy).toBe("abcdef123456");

    const parsedCli = TokenEngine.parseToken("mbk_cli_xyz789");
    expect(parsedCli.type).toBe("cli");

    const parsedUnknown = TokenEngine.parseToken("random_token");
    expect(parsedUnknown.type).toBe("custom");
  });

  test("extracts bearer token from authorization header", () => {
    expect(TokenEngine.extractBearerToken("Bearer token_abc")).toBe("token_abc");
    expect(TokenEngine.extractBearerToken("bearer token_xyz")).toBe("token_xyz");
    expect(TokenEngine.extractBearerToken("token_direct")).toBe("token_direct");
    expect(TokenEngine.extractBearerToken(null)).toBe("");
  });
});
