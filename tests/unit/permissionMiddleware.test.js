// Unit tests for the permission middleware (`permChk` / `checkPermission`).
// These middleware are pure-ish (no DB) once a session user is present, so they
// are exercised with fake req/res objects.
import { describe, it, expect } from "vitest";
import { checkPermission, checkRolePermission } from "../../lib/middleware/auth.js";

function callMiddleware(mw, req) {
  const res = { statusCode: null, body: null, rendered: null };
  let resolvePromise;
  const done = new Promise((resolve) => {
    resolvePromise = resolve;
  });
  res.status = function (code) { this.statusCode = code; return this; };
  res.json = function (payload) { this.body = payload; resolvePromise({ ok: false, res: this }); return this; };
  res.send = function (payload) { this.body = payload; resolvePromise({ ok: false, res: this }); return this; };
  res.render = function (view, model) { this.rendered = model; resolvePromise({ ok: false, res: this }); return this; };
  res.setHeader = () => res;
  mw(req, res, () => resolvePromise({ ok: true, res }));
  return done;
}

describe("permChk / checkPermission", () => {
  it("resolves the basic.access shorthand as a global permission", async () => {
    const req = {
      originalUrl: "/dashboard",
      session: { user: { username: "alice", role: "editor", permissions: { allows: ["global:basic:access"], denies: [] } } },
      headers: { accept: "text/html" },
    };
    const { ok } = await callMiddleware(checkPermission("basic.access"), req);
    expect(ok).toBe(true);
  });

  it("uses global basic access when no permission is supplied", async () => {
    const req = {
      originalUrl: "/dashboard",
      session: { user: { username: "alice", role: "editor", permissions: { allows: ["global:basic:access"], denies: [] } } },
      headers: { accept: "text/html" },
    };
    const { ok } = await callMiddleware(checkPermission(), req);
    expect(ok).toBe(true);
  });

  it("allows a matching permission", async () => {
    const req = {
      originalUrl: "/api/posts",
      session: { user: { username: "alice", role: "editor", permissions: { allows: ["blog:posts:delete"], denies: [] } } },
      headers: { accept: "application/json" },
    };
    const { ok } = await callMiddleware(checkPermission("blog:posts:delete"), req);
    expect(ok).toBe(true);
  });

  it("denies a missing permission with 403 JSON", async () => {
    const req = {
      originalUrl: "/api/posts",
      session: { user: { username: "alice", role: "editor", permissions: { allows: [], denies: [] } } },
      headers: { accept: "application/json" },
    };
    const { res } = await callMiddleware(checkPermission("blog:posts:delete"), req);
    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({ success: false });
  });

  it("names the required permission in the 403 JSON payload", async () => {
    const req = {
      originalUrl: "/dashboard",
      session: { user: { username: "alice", role: "editor", permissions: { allows: [], denies: [] } } },
      headers: { accept: "application/json" },
    };
    const { res } = await callMiddleware(checkPermission("basic.access"), req);
    expect(res.statusCode).toBe(403);
    expect(res.body.requiredPermission).toBe("global:basic:access");
    expect(res.body.message).toContain("global:basic:access");
  });

  it("names the required permission in the rendered 403 page", async () => {
    const req = {
      originalUrl: "/dashboard",
      session: { user: { username: "alice", role: "editor", permissions: { allows: [], denies: [] } } },
      headers: { accept: "text/html" },
    };
    const { res } = await callMiddleware(checkPermission("blog:posts:edit"), req);
    expect(res.statusCode).toBe(403);
    expect(res.rendered.message).toContain("blog:posts:edit");
  });

  it("names the required role in the 403 JSON payload", async () => {
    const req = {
      originalUrl: "/dashboard/admin",
      session: { user: { username: "alice", role: "normaluser" } },
      headers: { accept: "application/json" },
    };
    const { res } = await callMiddleware(checkRolePermission("superadmin"), req);
    expect(res.statusCode).toBe(403);
    expect(res.body.requiredRole).toBe("superadmin");
    expect(res.body.message).toContain("superadmin");
  });

  it("names every acceptable role when multiple are allowed", async () => {
    const req = {
      originalUrl: "/dashboard/admin",
      session: { user: { username: "alice", role: "guest" } },
      headers: { accept: "application/json" },
    };
    const { res } = await callMiddleware(checkRolePermission(["manager", "editor"]), req);
    expect(res.statusCode).toBe(403);
    expect(res.body.requiredRole).toEqual(["manager", "editor"]);
    expect(res.body.message).toContain("manager or editor");
  });

  it("names the disallowed role when blocked by notAllowed", async () => {
    const req = {
      originalUrl: "/dashboard",
      session: { user: { username: "guest", role: "guest" } },
      headers: { accept: "application/json" },
    };
    const { res } = await callMiddleware(checkRolePermission("any", "guest"), req);
    expect(res.statusCode).toBe(403);
    expect(res.body.notAllowedRole).toBe("guest");
    expect(res.body.message).toContain("guest");
  });

  it("deny override wins", async () => {
    const req = {
      originalUrl: "/api/posts",
      session: { user: { username: "alice", role: "editor", permissions: { allows: ["blog:posts:delete"], denies: ["blog:posts:delete"] } } },
      headers: { accept: "application/json" },
    };
    const { res } = await callMiddleware(checkPermission("blog:posts:delete"), req);
    expect(res.statusCode).toBe(403);
  });

  it("SuperAdmin bypasses even with no stored permissions", async () => {
    const req = {
      originalUrl: "/api/posts",
      session: { user: { username: "root", role: "superadmin" } },
      headers: { accept: "application/json" },
    };
    const { ok } = await callMiddleware(checkPermission("blog:posts:delete"), req);
    expect(ok).toBe(true);
  });

  it("401s when there is no session user", async () => {
    const req = { originalUrl: "/api/posts", session: {}, headers: { accept: "application/json" } };
    const { res } = await callMiddleware(checkPermission("blog:posts:delete"), req);
    expect(res.statusCode).toBe(401);
  });

  it("a permission-scoped API token user is authorized only for its permissions", async () => {
    const req = {
      originalUrl: "/api/dns",
      auth: { user: { username: "svc", role: "normaluser", permissions: { allows: ["portal:dns:view"], denies: [] } } },
      headers: { accept: "application/json" },
    };
    const allowed = await callMiddleware(checkPermission("portal:dns:view"), req);
    expect(allowed.ok).toBe(true);

    const denied = await callMiddleware(checkPermission("portal:dns:delete"), req);
    expect(denied.res.statusCode).toBe(403);
  });

  it("a legacy API token user (no permissions) is denied", async () => {
    const req = {
      originalUrl: "/api/dns",
      auth: { user: { username: "legacy", role: "normaluser" } },
      headers: { accept: "application/json" },
    };
    const { res } = await callMiddleware(checkPermission("portal:dns:view"), req);
    expect(res.statusCode).toBe(403);
  });
});
