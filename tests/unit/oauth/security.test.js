import { describe, it, expect, vi } from "vitest";
import { OAuthFlowService } from "../../../src/oauth/OAuthFlowService.js";
import { MemoryOAuthStateStore } from "../../../src/oauth/state/OAuthStateStore.js";

describe("OAuth Security & Attack Defenses", () => {
  it("rejects forged or missing state and emits oauth.suspicious", async () => {
    const emittedEvents = [];
    const mockEmit = (name, payload) => {
      emittedEvents.push({ name, payload });
    };

    const stateStore = new MemoryOAuthStateStore();
    const service = new OAuthFlowService({
      stateStore,
      emitEvent: mockEmit,
      providers: [
        {
          id: "google",
          name: "Google",
          isOidc: true,
          getAuthorizationUrl: () => "https://accounts.google.com/o/oauth2/v2/auth",
          exchangeCode: async () => ({ accessToken: "test" }),
          getUserInfo: async () => ({ provider: "google", id: "123", email: "test@example.com", emailVerified: true, name: "Test", username: "test", avatarUrl: null, raw: {} }),
        },
      ],
    });

    // Attempt callback with forged state
    await expect(
      service.complete("google", {
        code: "fake-code",
        state: "forged-state-value",
        redirectUri: "http://localhost:3000/callback",
      })
    ).rejects.toThrow(/security validation failed/i);

    // Verify suspicious and failure events were fired
    const suspicious = emittedEvents.find((e) => e.name === "oauth.suspicious");
    const failure = emittedEvents.find((e) => e.name === "oauth.callback.failure");

    expect(suspicious).toBeDefined();
    expect(suspicious.payload.provider).toBe("google");
    expect(failure).toBeDefined();
    expect(failure.payload.code).toBe("INVALID_STATE");
  });

  it("prevents state replay attack (state cannot be consumed twice)", async () => {
    const stateStore = new MemoryOAuthStateStore();
    const service = new OAuthFlowService({
      stateStore,
      providers: [
        {
          id: "github",
          name: "GitHub",
          isOidc: false,
          getAuthorizationUrl: () => "https://github.com/login/oauth/authorize",
          exchangeCode: async () => ({ accessToken: "test-token" }),
          getUserInfo: async () => ({ provider: "github", id: "gh-1", email: "user@github.com", emailVerified: true, name: "GH User", username: "ghuser", avatarUrl: null, raw: {} }),
        },
      ],
    });

    const beginResult = await service.begin("github", {
      redirectUri: "http://localhost:3000/auth/callback",
    });

    // Mock account repository to avoid db requirement
    service["accountRepo"] = {
      findByProvider: async () => ({ id: 1, userId: "existing_user", providerId: "github", providerUserId: "gh-1", profile: {} }),
      update: async (id, data) => data,
    };
    service["userRepo"] = {
      getUserWithTwoFA: async () => ({ username: "existing_user", role: "normaluser", is_active: true, allowed_apps: ["mbkauthe"] }),
    };

    // First completion succeeds
    const firstResult = await service.complete("github", {
      code: "valid-code",
      state: beginResult.state,
      redirectUri: "http://localhost:3000/auth/callback",
    });
    expect(firstResult.success).toBe(true);

    // Second completion with identical state MUST fail
    await expect(
      service.complete("github", {
        code: "valid-code",
        state: beginResult.state,
        redirectUri: "http://localhost:3000/auth/callback",
      })
    ).rejects.toThrow(/security validation failed/i);
  });

  it("rejects cross-provider state confusion (state generated for google used for github)", async () => {
    const stateStore = new MemoryOAuthStateStore();
    const emittedEvents = [];
    const service = new OAuthFlowService({
      stateStore,
      emitEvent: (name, p) => emittedEvents.push({ name, p }),
      providers: [
        { id: "google", name: "Google", isOidc: true, getAuthorizationUrl: () => "", exchangeCode: async () => ({ accessToken: "t" }), getUserInfo: async () => ({}) },
        { id: "github", name: "GitHub", isOidc: false, getAuthorizationUrl: () => "", exchangeCode: async () => ({ accessToken: "t" }), getUserInfo: async () => ({}) },
      ],
    });

    const googleBegin = await service.begin("google", { redirectUri: "http://localhost/cb" });

    // Try using Google's state with GitHub callback
    await expect(
      service.complete("github", {
        code: "auth-code",
        state: googleBegin.state,
        redirectUri: "http://localhost/cb",
      })
    ).rejects.toThrow(/state mismatch/i);

    const suspicious = emittedEvents.find((e) => e.name === "oauth.suspicious");
    expect(suspicious).toBeDefined();
  });
});
