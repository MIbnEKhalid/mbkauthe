import { describe, it, expect, beforeAll } from "vitest";
import express from "express";
import session from "express-session";
import cookieParser from "cookie-parser";
import request from "supertest";
import { createOAuthRouter } from "../../src/express/oauth.router.js";
import { OAuthFlowService } from "../../src/oauth/OAuthFlowService.js";
import { MemoryOAuthStateStore } from "../../src/oauth/state/OAuthStateStore.js";

describe("OAuth Express Adapter Router", () => {
  let app;
  let flowService;
  let stateStore;
  let mockAccounts = [];

  beforeAll(() => {
    stateStore = new MemoryOAuthStateStore();
    flowService = new OAuthFlowService({
      stateStore,
      providers: [
        {
          id: "testprovider",
          name: "Test Provider",
          isOidc: false,
          getAuthorizationUrl: (opts) => `https://testprovider.com/oauth/auth?state=${opts.state}`,
          exchangeCode: async () => ({ accessToken: "test-access-token", tokenType: "Bearer" }),
          getUserInfo: async () => ({
            provider: "testprovider",
            id: "tp_user_1",
            email: "user@testprovider.com",
            emailVerified: true,
            name: "Test Provider User",
            username: "tpuser",
            avatarUrl: null,
            raw: {},
          }),
        },
      ],
      accountRepo: {
        findByProvider: async (pId, pUserId) => mockAccounts.find((a) => a.providerId === pId && a.providerUserId === pUserId) || null,
        findByUserId: async (uId) => mockAccounts.filter((a) => a.userId === uId),
        findByUserAndProvider: async (uId, pId) => mockAccounts.find((a) => a.userId === uId && a.providerId === pId) || null,
        create: async (acc) => {
          const record = { ...acc, id: mockAccounts.length + 1 };
          mockAccounts.push(record);
          return record;
        },
        update: async (id, data) => data,
        delete: async (id) => {
          const idx = mockAccounts.findIndex((a) => a.id === Number(id));
          if (idx !== -1) {
            mockAccounts.splice(idx, 1);
            return true;
          }
          return false;
        },
        deleteByUserAndProvider: async (uId, pId) => {
          const idx = mockAccounts.findIndex((a) => a.userId === uId && a.providerId === pId);
          if (idx !== -1) {
            mockAccounts.splice(idx, 1);
            return true;
          }
          return false;
        },
      },
      userRepo: {
        getUserWithTwoFA: async (username) => ({
          username,
          user_id: "uid_1",
          role: "normaluser",
          is_active: true,
          allowed_apps: ["mbkauthe"],
          full_name: "Test User",
        }),
      },
    });

    app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use(cookieParser());
    app.use(
      session({
        secret: "test-session-secret",
        resave: false,
        saveUninitialized: true,
      })
    );

    // Middleware to simulate authenticated session if header present
    app.use((req, res, next) => {
      const mockAuthUser = req.headers["x-mock-user"];
      if (mockAuthUser) {
        req.session.user = {
          username: mockAuthUser,
          role: "normaluser",
          allowed_apps: ["mbkauthe"],
        };
      }
      next();
    });

    // Mount OAuth Router at /auth/oauth
    app.use("/auth/oauth", createOAuthRouter(flowService));
  });

  it("GET /auth/oauth/providers lists registered providers", async () => {
    const res = await request(app).get("/auth/oauth/providers");
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.providers).toEqual([
      { id: "testprovider", name: "Test Provider", isOidc: false },
    ]);
  });

  it("GET /auth/oauth/:provider/begin redirects to authorization URL", async () => {
    const res = await request(app).get("/auth/oauth/testprovider/begin?redirect=/dashboard");
    expect(res.status).toBe(302);
    expect(res.headers.location).toContain("https://testprovider.com/oauth/auth?state=");
  });

  it("GET /auth/oauth/:provider/begin returns JSON with Accept: application/json", async () => {
    const res = await request(app)
      .get("/auth/oauth/testprovider/begin")
      .set("Accept", "application/json");

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.authorizationUrl).toBeDefined();
    expect(res.body.data.state).toBeDefined();
  });

  it("POST /auth/oauth/:provider/link requires authentication", async () => {
    const res = await request(app)
      .post("/auth/oauth/testprovider/link")
      .set("Accept", "application/json");

    expect(res.status).toBe(401);
  });

  it("POST /auth/oauth/:provider/link initiates link flow for logged in user", async () => {
    const res = await request(app)
      .post("/auth/oauth/testprovider/link")
      .set("x-mock-user", "alice")
      .set("Accept", "application/json");

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.authorizationUrl).toBeDefined();
  });

  it("GET /auth/oauth/accounts lists linked accounts for authenticated user", async () => {
    mockAccounts.push({
      id: 99,
      userId: "alice",
      providerId: "testprovider",
      providerUserId: "tp_user_1",
      profile: { name: "Alice TP" },
    });

    const res = await request(app)
      .get("/auth/oauth/accounts")
      .set("x-mock-user", "alice");

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.accounts.length).toBe(1);
    expect(res.body.data.accounts[0].providerId).toBe("testprovider");
  });

  it("DELETE /auth/oauth/:provider unlinks account", async () => {
    const res = await request(app)
      .delete("/auth/oauth/testprovider")
      .set("x-mock-user", "alice");

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const listRes = await request(app)
      .get("/auth/oauth/accounts")
      .set("x-mock-user", "alice");

    expect(listRes.body.data.accounts.length).toBe(0);
  });
});
