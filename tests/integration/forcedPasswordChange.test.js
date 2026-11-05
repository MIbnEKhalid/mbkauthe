import request from "supertest";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { describe, it, expect, beforeEach, beforeAll } from "vitest";
import { readFile } from "fs/promises";
import dotenv from "dotenv";

dotenv.config = () => {};

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

process.env.test = "dev";
process.env.env = "dev";
delete process.env.mbkauthShared;

process.env.mbkautheVar = JSON.stringify({
  APP_NAME: "mbkauthe",
  MAIN_SECRET_TOKEN: "integration-main-secret-token",
  SESSION_SECRET_KEY: "integration-session-secret-key",
  IS_DEPLOYED: "false",
  DOMAIN: "localhost",
  DB_TYPE: "sqlite",
  SQLITE_PATH: ":memory:",
  COOKIE_EXPIRE_TIME: 2,
  MAX_SESSIONS_PER_USER: 5,
});

const {
  default: router,
  hashPassword,
  dblogin,
  sessVal,
} = await import("../../dist/index.js");

import { setupViewEngine } from "mbkutils";

describe("Ecosystem-Wide Forced Password Change in mbkauthe", () => {
  let app;
  const USERNAME = "mustchangeuser";
  const PASSWORD = "InitialPassword123!";

  beforeAll(async () => {
    const SCHEMA_PATH = path.join(__dirname, "../../docs/schema/sqlite.sql");
    const schemaSql = await readFile(SCHEMA_PATH, "utf8");
    dblogin.execScript(schemaSql);
  });

  beforeEach(async () => {
    app = express();
    setupViewEngine(app, {
      viewsDir: path.join(__dirname, "../../views"),
      appName: "mbkauthe",
    });

    app.use(router);

    // Protected HTML route in host app
    app.get("/portal/dashboard", sessVal, (req, res) => {
      res.send("<h1>Welcome to Protected Dashboard</h1>");
    });

    // Protected API route in host app
    app.get("/api/portal/data", sessVal, (req, res) => {
      res.json({ success: true, data: "sensitive-info" });
    });

    // Seed test user with must_change_password = 1
    await dblogin.query("DELETE FROM mbkcore_users WHERE username = $1", [USERNAME]);
    await dblogin.query(
      `INSERT INTO mbkcore_users (username, password_hash, role, is_active, is_local_only, allowed_apps, full_name, must_change_password)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [USERNAME, hashPassword(PASSWORD, USERNAME), "normaluser", 1, 0, JSON.stringify(["Portal", "mbkauthe"]), "Must Change", 1]
    );
  });

  it("intercepts login for users flagged with must_change_password and directs to change-password", async () => {
    const agent = request.agent(app);

    const loginRes = await agent
      .post("/mbkauthe/api/login")
      .send({ username: USERNAME, password: PASSWORD });

    expect(loginRes.status).toBe(200);
    expect(loginRes.body.success).toBe(true);
    expect(loginRes.body.must_change_password).toBe(true);
    expect(loginRes.body.redirect_url).toContain("/mbkauthe/change-password");

    // Navigating to /mbkauthe/change-password renders 200 with the Change Password page
    const changePageRes = await agent.get("/mbkauthe/change-password").set("Accept", "text/html");
    expect(changePageRes.status).toBe(200);

    // Visiting /mbkauthe/login while flagged with must_change_password immediately redirects to /mbkauthe/change-password
    const loginPageRes = await agent.get("/mbkauthe/login").set("Accept", "text/html");
    expect(loginPageRes.status).toBe(302);
    expect(loginPageRes.header.location).toContain("/mbkauthe/change-password");

    // Attempting to access protected HTML page redirects to /mbkauthe/change-password
    const pageRes = await agent.get("/portal/dashboard").set("Accept", "text/html");
    expect(pageRes.status).toBe(302);
    expect(pageRes.header.location).toContain("/mbkauthe/change-password");

    // Attempting to access protected API returns 403 MUST_CHANGE_PASSWORD
    const apiRes = await agent.get("/api/portal/data").set("Accept", "application/json");
    expect(apiRes.status).toBe(403);
    expect(apiRes.body.errorCode).toBe(903);

    // Changing password via mbkauthe API
    const changeRes = await agent
      .post("/mbkauthe/api/change-password")
      .send({ newPassword: "BrandNewPassword123!", confirmPassword: "BrandNewPassword123!" });

    expect(changeRes.status).toBe(200);
    expect(changeRes.body.success).toBe(true);

    // Now protected HTML page is accessible
    const pageAfter = await agent.get("/portal/dashboard").set("Accept", "text/html");
    expect(pageAfter.status).toBe(200);
    expect(pageAfter.text).toContain("Welcome to Protected Dashboard");

    // Now protected API is accessible
    const apiAfter = await agent.get("/api/portal/data").set("Accept", "application/json");
    expect(apiAfter.status).toBe(200);
    expect(apiAfter.body.data).toBe("sensitive-info");
  });
});
