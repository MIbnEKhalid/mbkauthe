import { describe, it, expect, beforeEach } from "vitest";
import { MemoryOAuthStateStore } from "../../../src/oauth/state/OAuthStateStore.js";

describe("OAuth State & PKCE Store", () => {
  let store;

  beforeEach(() => {
    store = new MemoryOAuthStateStore({ defaultTtlSeconds: 2 });
  });

  it("generates cryptographic PKCE code_verifier and S256 code_challenge", () => {
    const pkce = store.generatePkce();
    expect(pkce.codeVerifier).toBeDefined();
    expect(pkce.codeVerifier.length).toBeGreaterThanOrEqual(32);
    expect(pkce.codeChallenge).toBeDefined();
    expect(pkce.codeChallengeMethod).toBe("S256");
    // Challenge should not equal verifier
    expect(pkce.codeChallenge).not.toBe(pkce.codeVerifier);
  });

  it("generates cryptographic nonce for OIDC", () => {
    const nonce1 = store.generateNonce();
    const nonce2 = store.generateNonce();
    expect(nonce1).toBeDefined();
    expect(nonce1.length).toBeGreaterThanOrEqual(16);
    expect(nonce1).not.toBe(nonce2);
  });

  it("stores state data and retrieves it exactly once (one-time use)", async () => {
    const state = await store.generateState({
      providerId: "google",
      redirectUri: "http://localhost:3000/auth/callback",
      codeVerifier: "test-verifier",
      nonce: "test-nonce",
      returnTo: "/dashboard",
      action: "login",
    });

    expect(state).toBeDefined();
    expect(store.size).toBe(1);

    // First consumption: success
    const retrieved = await store.verifyAndConsumeState(state);
    expect(retrieved).not.toBeNull();
    expect(retrieved?.providerId).toBe("google");
    expect(retrieved?.codeVerifier).toBe("test-verifier");
    expect(retrieved?.nonce).toBe("test-nonce");
    expect(retrieved?.returnTo).toBe("/dashboard");
    expect(retrieved?.action).toBe("login");

    // Second consumption: fails (one-time use)
    const secondRetrieval = await store.verifyAndConsumeState(state);
    expect(secondRetrieval).toBeNull();
    expect(store.size).toBe(0);
  });

  it("rejects non-existent or null state", async () => {
    expect(await store.verifyAndConsumeState("non-existent-state")).toBeNull();
    expect(await store.verifyAndConsumeState(null)).toBeNull();
    expect(await store.verifyAndConsumeState(undefined)).toBeNull();
    expect(await store.verifyAndConsumeState("")).toBeNull();
  });

  it("expires state when TTL is exceeded", async () => {
    const state = await store.generateState(
      {
        providerId: "github",
        redirectUri: "http://localhost:3000/auth/callback",
      },
      1 // 1 second TTL
    );

    // Wait 1.1s for expiration
    await new Promise((resolve) => setTimeout(resolve, 1100));

    const retrieved = await store.verifyAndConsumeState(state);
    expect(retrieved).toBeNull();
  });
});
