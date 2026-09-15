import { describe, it, expect } from "vitest";
import { loadOAuthProvidersFromConfig, isOAuthProviderConfigured, getEnabledOAuthProvidersUI } from "../../../dist/oauth/providers/loader.js";

describe("OAuth Provider Config Loader", () => {
  it("loads GitHub and Google from uppercase user format like { GITHUB: { LOGIN_ENABLED: 'true', CLIENT_ID: '...', CLIENT_SECRET: '...' } }", () => {
    const config = {
      GITHUB: {
        LOGIN_ENABLED: "true",
        CLIENT_ID: "gh-app-client-id",
        CLIENT_SECRET: "gh-app-client-secret",
      },
      GOOGLE: {
        LOGIN_ENABLED: "true",
        CLIENT_ID: "gg-client-id",
        CLIENT_SECRET: "gg-client-secret",
      },
    };

    const providers = loadOAuthProvidersFromConfig(config);
    expect(providers.length).toBe(2);

    const gh = providers.find((p) => p.id === "github");
    const gg = providers.find((p) => p.id === "google");

    expect(gh).toBeDefined();
    expect(gh?.name).toBe("GitHub");
    expect(gh?.["clientId"]).toBe("gh-app-client-id");

    expect(gg).toBeDefined();
    expect(gg?.name).toBe("Google");
    expect(gg?.isOidc).toBe(true);
    expect(gg?.["clientId"]).toBe("gg-client-id");
  });

  it("loads Microsoft with custom tenant", () => {
    const config = {
      microsoft: {
        login_enabled: true,
        client_id: "ms-client-123",
        client_secret: "ms-secret-456",
        tenant: "my-tenant-uuid",
      },
    };

    const providers = loadOAuthProvidersFromConfig(config);
    expect(providers.length).toBe(1);
    expect(providers[0].id).toBe("microsoft");
    expect(providers[0]["issuer"]).toBe("https://login.microsoftonline.com/my-tenant-uuid/v2.0");
  });

  it("loads Discord and Apple presets", () => {
    const config = {
      discord: {
        enabled: "true",
        clientId: "disc-id",
        clientSecret: "disc-sec",
      },
      apple: {
        login_enabled: true,
        clientId: "apple-client",
        clientSecret: "apple-sec",
      },
    };

    const providers = loadOAuthProvidersFromConfig(config);
    expect(providers.length).toBe(2);
    expect(providers.some((p) => p.id === "discord")).toBe(true);
    expect(providers.some((p) => p.id === "apple")).toBe(true);
  });

  it("loads Custom OIDC provider with issuer and custom scopes", () => {
    const config = {
      keycloak: {
        type: "oidc",
        name: "Enterprise SSO",
        issuer: "https://auth.enterprise.com/realms/main",
        client_id: "ent-client",
        client_secret: "ent-secret",
        scopes: ["openid", "profile", "email", "roles"],
      },
    };

    const providers = loadOAuthProvidersFromConfig(config);
    expect(providers.length).toBe(1);
    expect(providers[0].id).toBe("keycloak");
    expect(providers[0].name).toBe("Enterprise SSO");
    expect(providers[0]["issuer"]).toBe("https://auth.enterprise.com/realms/main");
    expect(providers[0].isOidc).toBe(true);
  });

  it("skips disabled providers or providers without client_id", () => {
    const config = {
      github: {
        login_enabled: "false",
        client_id: "gh-id",
        client_secret: "gh-sec",
      },
      google: {
        login_enabled: "true",
        // missing client_id
        client_secret: "gg-sec",
      },
      discord: {
        enabled: false,
        client_id: "disc-id",
        client_secret: "disc-sec",
      },
    };

    const providers = loadOAuthProvidersFromConfig(config);
    expect(providers.length).toBe(0);
  });

  it("isOAuthProviderConfigured checks presence and enabled status correctly", () => {
    const config = {
      GITHUB: {
        LOGIN_ENABLED: "true",
        CLIENT_ID: "gh-1",
      },
      GOOGLE: {
        LOGIN_ENABLED: "false",
        CLIENT_ID: "gg-1",
      },
    };

    expect(isOAuthProviderConfigured("github", config)).toBe(true);
    expect(isOAuthProviderConfigured("google", config)).toBe(false);
    expect(isOAuthProviderConfigured("discord", config)).toBe(false);
    expect(isOAuthProviderConfigured("github", null)).toBe(false);
  });

  it("getEnabledOAuthProvidersUI returns structured UI items for all enabled providers", () => {
    const config = {
      GITHUB: {
        LOGIN_ENABLED: "true",
        CLIENT_ID: "gh-1",
      },
      GOOGLE: {
        LOGIN_ENABLED: "true",
        CLIENT_ID: "gg-1",
      },
      MICROSOFT: {
        LOGIN_ENABLED: "true",
        CLIENT_ID: "ms-1",
      },
      DISCORD: {
        LOGIN_ENABLED: "false",
        CLIENT_ID: "dc-1",
      },
    };

    const items = getEnabledOAuthProvidersUI(config, "github");
    expect(items.length).toBe(3);

    const gh = items.find((i) => i.id === "github");
    expect(gh).toBeDefined();
    expect(gh?.name).toBe("GitHub");
    expect(gh?.displayName).toBe("Login with GitHub");
    expect(gh?.iconClass).toBe("fab fa-github");
    expect(gh?.loginUrl).toBe("/mbkauthe/oauth/github/begin");
    expect(gh?.isLastUsed).toBe(true);

    const gg = items.find((i) => i.id === "google");
    expect(gg).toBeDefined();
    expect(gg?.isLastUsed).toBe(false);

    const ms = items.find((i) => i.id === "microsoft");
    expect(ms).toBeDefined();
    expect(ms?.iconClass).toBe("fab fa-microsoft");
  });
});
