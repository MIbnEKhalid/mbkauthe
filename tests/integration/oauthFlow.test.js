import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import * as jose from "jose";
import { OAuthFlowService } from "../../src/oauth/OAuthFlowService.js";
import { OIDCProvider } from "../../src/oauth/providers/OIDCProvider.js";
import { MemoryOAuthStateStore } from "../../src/oauth/state/OAuthStateStore.js";
import { AesGcmTokenEncryptor } from "../../src/oauth/crypto/tokenEncryption.js";

describe("OAuth & OIDC Integration Flow", () => {
  let mockServer;
  let serverPort;
  let keyPair;
  let publicJwk;
  let oidcProvider;
  let flowService;
  let mockAccounts = new Map();
  let mockUsers = new Map();
  let lastAuthNonce = null;

  beforeAll(async () => {
    // Generate RSA keys for Mock OIDC server
    keyPair = await jose.generateKeyPair("RS256");
    publicJwk = await jose.exportJWK(keyPair.publicKey);
    publicJwk.kid = "mock-key-1";
    publicJwk.alg = "RS256";
    publicJwk.use = "sig";

    // Setup Mock OIDC Server
    mockServer = http.createServer(async (req, res) => {
      const url = new URL(req.url, `http://localhost:${serverPort}`);

      if (url.pathname === "/.well-known/openid-configuration") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(
          JSON.stringify({
            issuer: `http://localhost:${serverPort}`,
            authorization_endpoint: `http://localhost:${serverPort}/authorize`,
            token_endpoint: `http://localhost:${serverPort}/token`,
            userinfo_endpoint: `http://localhost:${serverPort}/userinfo`,
            jwks_uri: `http://localhost:${serverPort}/jwks`,
          })
        );
      }

      if (url.pathname === "/jwks") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ keys: [publicJwk] }));
      }

      if (url.pathname === "/authorize") {
        lastAuthNonce = url.searchParams.get("nonce");
        res.writeHead(302, { Location: `${url.searchParams.get("redirect_uri")}?code=mock_code&state=${url.searchParams.get("state")}` });
        return res.end();
      }


      if (url.pathname === "/token" && req.method === "POST") {
        let body = "";
        req.on("data", (chunk) => { body += chunk; });
        req.on("end", async () => {
          const params = new URLSearchParams(body);
          const code = params.get("code");
          const nonce = params.get("nonce") || lastAuthNonce;



          const now = Math.floor(Date.now() / 1000);
          const claims = {
            sub: "mock_oidc_user_42",
            email: "sammock@mockidp.com",
            email_verified: true,
            name: "Sam Mock",
            preferred_username: "sammock",
            nonce: nonce || lastAuthNonce || "test-nonce",
          };


          const idToken = await new jose.SignJWT(claims)
            .setProtectedHeader({ alg: "RS256", kid: "mock-key-1" })
            .setIssuer(`http://localhost:${serverPort}`)
            .setAudience("mock-client-id")
            .setIssuedAt(now)
            .setExpirationTime(now + 3600)
            .sign(keyPair.privateKey);



          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              access_token: "mock-access-token-xyz",
              token_type: "Bearer",
              expires_in: 3600,
              id_token: idToken,
              refresh_token: "mock-refresh-token-123",
            })
          );
        });
        return;
      }

      if (url.pathname === "/userinfo") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(
          JSON.stringify({
            sub: "mock_oidc_user_42",
            email: "sammock@mockidp.com",
            email_verified: true,
            name: "Sam Mock",
            preferred_username: "sammock",

          })
        );
      }

      res.writeHead(404);
      res.end();
    });

    await new Promise((resolve) => {
      mockServer.listen(0, () => {
        serverPort = mockServer.address().port;
        resolve();
      });
    });

    // Seed test users
    mockUsers.set("sammock", {
      username: "sammock",
      user_id: "u_sammock",
      role: "normaluser",
      is_active: true,
      allowed_apps: ["mbkauthe"],
    });

    // Mock Repositories
    const mockAccountRepo = {
      findByProvider: async (pId, pUserId) => {
        const key = `${pId}:${pUserId}`;
        return mockAccounts.get(key) || null;
      },
      findByUserId: async (uId) => {
        return Array.from(mockAccounts.values()).filter((a) => a.userId === uId);
      },
      findByUserAndProvider: async (uId, pId) => {
        return (
          Array.from(mockAccounts.values()).find(
            (a) => a.userId === uId && a.providerId === pId
          ) || null
        );
      },
      create: async (acc) => {
        const record = { ...acc, id: mockAccounts.size + 1, createdAt: new Date(), updatedAt: new Date() };
        mockAccounts.set(`${acc.providerId}:${acc.providerUserId}`, record);
        return record;
      },
      update: async (id, data) => {
        for (const [k, v] of mockAccounts.entries()) {
          if (v.id === id) {
            const updated = { ...v, ...data, updatedAt: new Date() };
            mockAccounts.set(k, updated);
            return updated;
          }
        }
        return data;
      },
      delete: async (id) => {
        for (const [k, v] of mockAccounts.entries()) {
          if (v.id === id) {
            mockAccounts.delete(k);
            return true;
          }
        }
        return false;
      },
      deleteByUserAndProvider: async (uId, pId) => {
        for (const [k, v] of mockAccounts.entries()) {
          if (v.userId === uId && v.providerId === pId) {
            mockAccounts.delete(k);
            return true;
          }
        }
        return false;
      },
    };

    const mockUserRepo = {
      getUserWithTwoFA: async (username) => mockUsers.get(username) || null,
      getUserByUsername: async (username) => mockUsers.get(username) || null,
    };

    oidcProvider = new OIDCProvider({
      id: "mockidp",
      name: "Mock IDP",
      issuer: `http://localhost:${serverPort}`,
      clientId: "mock-client-id",
      clientSecret: "mock-client-secret",
    });

    flowService = new OAuthFlowService({
      providers: [oidcProvider],
      stateStore: new MemoryOAuthStateStore(),
      accountRepo: mockAccountRepo,
      userRepo: mockUserRepo,
      encryptor: new AesGcmTokenEncryptor("test-secret-key-1234"),
      allowAutoLinkByEmail: true,
    });
  });

  afterAll(async () => {
    if (mockServer) {
      await new Promise((resolve) => mockServer.close(resolve));
    }
  });

  it("completes full OIDC flow: begin -> exchange -> auto-link by email -> login", async () => {
    // 1. Begin flow
    const beginRes = await flowService.begin("mockidp", {
      redirectUri: "http://localhost:3000/auth/callback",
      returnTo: "/dashboard",
    });

    const authUrl = new URL(beginRes.authorizationUrl);
    lastAuthNonce = authUrl.searchParams.get("nonce");

    expect(beginRes.authorizationUrl).toContain(`http://localhost:${serverPort}/authorize`);
    expect(beginRes.state).toBeDefined();


    // 2. Complete flow with authorization code
    const completeRes = await flowService.complete("mockidp", {
      code: "valid-auth-code-123",
      state: beginRes.state,
      redirectUri: "http://localhost:3000/auth/callback",
    });

    expect(completeRes.success).toBe(true);
    expect(completeRes.user.username).toBe("sammock");
    expect(completeRes.profile.id).toBe("mock_oidc_user_42");
    expect(completeRes.tokens.accessToken).toBe("mock-access-token-xyz");
    expect(completeRes.returnTo).toBe("/dashboard");

    // 3. Verify account was saved and encrypted at rest
    const accounts = await flowService.listAccounts("sammock");
    expect(accounts.length).toBe(1);
    expect(accounts[0].providerId).toBe("mockidp");
    expect(accounts[0].providerUserId).toBe("mock_oidc_user_42");

    // 4. Unlink account
    const unlinked = await flowService.unlink("sammock", "mockidp");
    expect(unlinked).toBe(true);

    const accountsAfterUnlink = await flowService.listAccounts("sammock");
    expect(accountsAfterUnlink.length).toBe(0);
  });
});
