import { describe, it, expect } from "vitest";
import { googleProvider, githubProvider, microsoftProvider, discordProvider, appleProvider, customOIDCProvider } from "../../../src/oauth/providers/index.js";

describe("OAuth & OIDC Presets Normalization", () => {
  it("googleProvider generates normalized profile", async () => {
    const provider = googleProvider({
      clientId: "google-client-id",
      clientSecret: "google-secret",
    });

    expect(provider.id).toBe("google");
    expect(provider.isOidc).toBe(true);

    const rawGoogle = {
      sub: "109823749817234",
      email: "jane.doe@gmail.com",
      email_verified: true,
      name: "Jane Doe",
      given_name: "Jane",
      family_name: "Doe",
      picture: "https://lh3.googleusercontent.com/a/sample-photo",
    };

    const profile = await provider.getUserInfo({
      accessToken: "ya29.sample",
      raw: { idTokenClaims: rawGoogle },
    });

    expect(profile).toEqual({
      provider: "google",
      id: "109823749817234",
      email: "jane.doe@gmail.com",
      emailVerified: true,
      name: "Jane Doe",
      username: "jane.doe",
      avatarUrl: "https://lh3.googleusercontent.com/a/sample-photo",
      raw: rawGoogle,
    });
  });

  it("githubProvider generates normalized profile", async () => {
    const provider = githubProvider({
      clientId: "github-client-id",
      clientSecret: "github-secret",
    });

    expect(provider.id).toBe("github");
    expect(provider.isOidc).toBe(false);

    const rawGithub = {
      id: 583231,
      login: "octocat",
      name: "The Octocat",
      email: "octocat@github.com",
      avatar_url: "https://avatars.githubusercontent.com/u/583231",
    };

    // Mock http client / profileParser
    const profile = await provider["profileParser"](rawGithub, { accessToken: "gho_sample" });

    expect(profile).toEqual({
      provider: "github",
      id: "583231",
      email: "octocat@github.com",
      emailVerified: true,
      name: "The Octocat",
      username: "octocat",
      avatarUrl: "https://avatars.githubusercontent.com/u/583231",
      raw: rawGithub,
    });
  });

  it("microsoftProvider generates normalized profile", async () => {
    const provider = microsoftProvider({
      clientId: "ms-client-id",
      clientSecret: "ms-secret",
    });

    expect(provider.id).toBe("microsoft");
    expect(provider.isOidc).toBe(true);

    const rawMs = {
      sub: "ms-sub-id-123",
      email: "john@corp.microsoft.com",
      name: "John Smith",
      preferred_username: "john@corp.microsoft.com",
    };

    const profile = await provider["profileParser"](rawMs, { accessToken: "ms_token" });

    expect(profile).toEqual({
      provider: "microsoft",
      id: "ms-sub-id-123",
      email: "john@corp.microsoft.com",
      emailVerified: true,
      name: "John Smith",
      username: "john",
      avatarUrl: null,
      raw: rawMs,
    });
  });

  it("discordProvider generates normalized profile", async () => {
    const provider = discordProvider({
      clientId: "discord-client-id",
      clientSecret: "discord-secret",
    });

    expect(provider.id).toBe("discord");
    expect(provider.isOidc).toBe(false);

    const rawDiscord = {
      id: "80351110224678912",
      username: "nelly",
      global_name: "Nelly Gamer",
      avatar: "834272909634935424",
      email: "nelly@discord.com",
      verified: true,
    };

    const profile = await provider["profileParser"](rawDiscord, { accessToken: "discord_token" });

    expect(profile).toEqual({
      provider: "discord",
      id: "80351110224678912",
      email: "nelly@discord.com",
      emailVerified: true,
      name: "Nelly Gamer",
      username: "nelly",
      avatarUrl: "https://cdn.discordapp.com/avatars/80351110224678912/834272909634935424.png",
      raw: rawDiscord,
    });
  });

  it("appleProvider generates normalized profile", async () => {
    const provider = appleProvider({
      clientId: "com.example.app",
      clientSecret: "apple-client-secret",
    });

    expect(provider.id).toBe("apple");
    expect(provider.isOidc).toBe(true);

    const rawApple = {
      sub: "001234.apple.user.sub",
      email: "user@privaterelay.appleid.com",
      email_verified: "true",
      name: { firstName: "Tim", lastName: "Apple" },
    };

    const profile = await provider["profileParser"](rawApple, { accessToken: "apple_token" });

    expect(profile).toEqual({
      provider: "apple",
      id: "001234.apple.user.sub",
      email: "user@privaterelay.appleid.com",
      emailVerified: true,
      name: "Tim Apple",
      username: "user",
      avatarUrl: null,
      raw: rawApple,
    });
  });

  it("customOIDCProvider creates flexible OIDC provider", async () => {
    const provider = customOIDCProvider({
      id: "keycloak",
      name: "Keycloak Enterprise",
      issuer: "https://sso.example.com/realms/master",
      clientId: "my-client",
      clientSecret: "my-secret",
    });

    expect(provider.id).toBe("keycloak");
    expect(provider.name).toBe("Keycloak Enterprise");
    expect(provider.isOidc).toBe(true);
  });
});
