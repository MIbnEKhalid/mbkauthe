import { describe, test, expect, beforeAll, afterAll } from "vitest";
import path from "path";
import { fileURLToPath } from "url";
import { readFile } from "fs/promises";
import { SqlitePool, AuthRepository, ApiTokenRepository, CliAuthSessionRepository, AuthService, ApiTokenService, OAuthService, CliAuthService, getAuthHealthReport, hashPassword } from "../../dist/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SCHEMA_PATH = path.join(__dirname, "../../docs/schema/db.sqlite.sql");

describe("Service Layer & Diagnostics", () => {
  let pool;
  let authRepo;
  let tokenRepo;
  let cliRepo;
  let authService;
  let apiTokenService;
  let cliAuthService;
  let oAuthService;

  beforeAll(async () => {
    const schemaSql = await readFile(SCHEMA_PATH, "utf8");
    pool = new SqlitePool(":memory:");
    pool.execScript(schemaSql);

    const dialect = { name: "sqlite" };
    authRepo = new AuthRepository({ db: pool, dialect });
    tokenRepo = new ApiTokenRepository({ db: pool, dialect });
    cliRepo = new CliAuthSessionRepository({ db: pool, dialect });

    authService = new AuthService(authRepo);
    apiTokenService = new ApiTokenService(tokenRepo, authRepo);
    cliAuthService = new CliAuthService(cliRepo, apiTokenService);
    oAuthService = new OAuthService(authRepo);
  });

  afterAll(async () => {
    if (pool) await pool.end().catch(() => {});
  });

  test("getAuthHealthReport returns health status and diagnostic info", async () => {
    const report = await getAuthHealthReport();
    expect(report.status).toBeDefined();
    expect(report.version).toBeDefined();
    expect(report.dialect).toBeDefined();
  });

  test("OAuthService resolves enabled providers", () => {
    const providers = oAuthService.getEnabledProviders();
    expect(Array.isArray(providers)).toBe(true);
  });

  test("AuthService, ApiTokenService, and CliAuthService lifecycle", async () => {
    // Seed user
    const username = "service_test_user";
    const password = "ServicePassword123!";
    await pool.query(
      `INSERT INTO mbkcore_users (username, password_hash, role, is_active, allowed_apps, full_name)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [username, hashPassword(password, username), "admin", 1, JSON.stringify(["Portal", "mbkauthe"]), "Service User"]
    );

    // Seed CLI profile
    const profileKey = "svcprof01";
    await pool.query(
      `INSERT INTO mbkcore_api_token_profiles (profile_key, name, description, permissions, expires_in_days, is_active)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [profileKey, "Service Profile", "Profile for service test", JSON.stringify(["portal:read"]), 30, 1]
    );

    // 1. AuthService login
    const loginResult = await authService.loginWithPassword(
      { username, password },
      { appKey: "mbkauthe", ip: "127.0.0.1" }
    );
    expect(loginResult.requires2FA).toBe(false);
    expect(loginResult.appSessionId).toBeDefined();

    // 2. ApiTokenService create & list & authenticate
    const tokenResult = await apiTokenService.createToken(username, {
      name: "Service PAT",
      scopes: ["portal:read"],
      expiresInDays: 7,
    });
    expect(tokenResult.token.startsWith("mbk_pat_")).toBe(true);

    const userTokens = await apiTokenService.listUserTokens(username);
    expect(userTokens.length).toBeGreaterThanOrEqual(1);

    const authedUser = await apiTokenService.authenticateRawToken(tokenResult.token);
    expect(authedUser).toBeDefined();
    expect(authedUser.username).toBe(username);

    // 3. CliAuthService initiate and poll
    const cliInit = await cliAuthService.initiate({ clientName: "Test CLI", profileKey });
    expect(cliInit.device_code).toBeDefined();
    expect(cliInit.user_code).toBeDefined();

    const pollPending = await cliAuthService.poll(cliInit.device_code);
    expect(pollPending.status).toBe("pending");

    // Approve
    const approved = await cliAuthService.approve(cliInit.user_code, username);
    expect(approved).toBe(true);

    const pollApproved = await cliAuthService.poll(cliInit.device_code);
    expect(pollApproved.status).toBe("approved");
    expect(pollApproved.access_token).toBeDefined();

    // 4. Cleanup
    await authService.logoutSession(loginResult.appSessionId, username);
  });
});
