import { describe, it, expect, beforeAll } from "vitest";
import * as jose from "jose";
import { OIDCProvider } from "../../../src/oauth/providers/OIDCProvider.js";

describe("OIDC Provider & ID Token Verification (jose)", () => {
  let keyPair;
  let publicJwk;
  let keySet;

  beforeAll(async () => {
    keyPair = await jose.generateKeyPair("RS256");
    publicJwk = await jose.exportJWK(keyPair.publicKey);
    publicJwk.kid = "test-key-1";
    publicJwk.alg = "RS256";
    publicJwk.use = "sig";

    keySet = jose.createLocalJWKSet({
      keys: [publicJwk],
    });
  });

  it("verifies a valid signed ID Token with claims and nonce", async () => {
    const provider = new OIDCProvider({
      id: "test-oidc",
      name: "Test OIDC",
      issuer: "https://idp.example.com",
      clientId: "my-app-client-id",
      clientSecret: "my-app-client-secret",
      jwksKeySet: keySet,
    });

    const now = Math.floor(Date.now() / 1000);
    const idToken = await new jose.SignJWT({
      sub: "user_98765",
      email: "alex@example.com",
      email_verified: true,
      name: "Alex Rivera",
      nonce: "secure-nonce-123",
    })
      .setProtectedHeader({ alg: "RS256", kid: "test-key-1" })
      .setIssuer("https://idp.example.com")
      .setAudience("my-app-client-id")
      .setIssuedAt(now)
      .setExpirationTime(now + 3600)
      .sign(keyPair.privateKey);

    const claims = await provider.verifyIdToken(idToken, "secure-nonce-123");
    expect(claims.sub).toBe("user_98765");
    expect(claims.email).toBe("alex@example.com");
    expect(claims.nonce).toBe("secure-nonce-123");
  });

  it("rejects ID Token with mismatched nonce", async () => {
    const provider = new OIDCProvider({
      id: "test-oidc",
      name: "Test OIDC",
      issuer: "https://idp.example.com",
      clientId: "my-app-client-id",
      clientSecret: "my-app-client-secret",
      jwksKeySet: keySet,
    });

    const now = Math.floor(Date.now() / 1000);
    const idToken = await new jose.SignJWT({
      sub: "user_98765",
      nonce: "actual-nonce",
    })
      .setProtectedHeader({ alg: "RS256", kid: "test-key-1" })
      .setIssuer("https://idp.example.com")
      .setAudience("my-app-client-id")
      .setIssuedAt(now)
      .setExpirationTime(now + 3600)
      .sign(keyPair.privateKey);

    await expect(provider.verifyIdToken(idToken, "expected-different-nonce")).rejects.toThrow(
      /nonce mismatch/i
    );
  });

  it("rejects ID Token with wrong audience", async () => {
    const provider = new OIDCProvider({
      id: "test-oidc",
      name: "Test OIDC",
      issuer: "https://idp.example.com",
      clientId: "my-app-client-id",
      clientSecret: "my-app-client-secret",
      jwksKeySet: keySet,
    });

    const now = Math.floor(Date.now() / 1000);
    const idToken = await new jose.SignJWT({
      sub: "user_98765",
    })
      .setProtectedHeader({ alg: "RS256", kid: "test-key-1" })
      .setIssuer("https://idp.example.com")
      .setAudience("another-client-id") // Wrong audience
      .setIssuedAt(now)
      .setExpirationTime(now + 3600)
      .sign(keyPair.privateKey);

    await expect(provider.verifyIdToken(idToken)).rejects.toThrow(/validation failed/i);
  });

  it("rejects expired ID Token", async () => {
    const provider = new OIDCProvider({
      id: "test-oidc",
      name: "Test OIDC",
      issuer: "https://idp.example.com",
      clientId: "my-app-client-id",
      clientSecret: "my-app-client-secret",
      jwksKeySet: keySet,
    });

    const past = Math.floor(Date.now() / 1000) - 3600;
    const idToken = await new jose.SignJWT({
      sub: "user_98765",
    })
      .setProtectedHeader({ alg: "RS256", kid: "test-key-1" })
      .setIssuer("https://idp.example.com")
      .setAudience("my-app-client-id")
      .setIssuedAt(past - 60)
      .setExpirationTime(past) // Expired 1 hour ago
      .sign(keyPair.privateKey);

    await expect(provider.verifyIdToken(idToken)).rejects.toThrow(/validation failed/i);
  });

  it("rejects ID Token signed by unknown key", async () => {
    const otherKeyPair = await jose.generateKeyPair("RS256");
    const provider = new OIDCProvider({
      id: "test-oidc",
      name: "Test OIDC",
      issuer: "https://idp.example.com",
      clientId: "my-app-client-id",
      clientSecret: "my-app-client-secret",
      jwksKeySet: keySet,
    });

    const now = Math.floor(Date.now() / 1000);
    const idToken = await new jose.SignJWT({
      sub: "user_98765",
    })
      .setProtectedHeader({ alg: "RS256", kid: "unknown-key" })
      .setIssuer("https://idp.example.com")
      .setAudience("my-app-client-id")
      .setIssuedAt(now)
      .setExpirationTime(now + 3600)
      .sign(otherKeyPair.privateKey);

    await expect(provider.verifyIdToken(idToken)).rejects.toThrow(/validation failed/i);
  });
});
