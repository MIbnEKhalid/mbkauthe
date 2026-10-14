// Unit tests for the bitmask permission middleware (`permChk` / `checkPermission`).
import { describe, it, expect } from "vitest";
import { checkPermission, checkRolePermission, defineResource } from "../../dist/index.js";

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

const Posts = defineResource("posts", {
  view: 1,
  create: 2,
  edit: 4,
  delete: 8,
});

describe("permChk / checkPermission", () => {
  it("allows a user with matching action bit", async () => {
    const req = {
      originalUrl: "/api/posts",
      session: { user: { username: "alice", role: "editor", perms: { posts: Posts.actions.delete.mask } } },
      headers: { accept: "application/json" },
    };
    const { ok } = await callMiddleware(checkPermission(Posts.actions.delete), req);
    expect(ok).toBe(true);
  });

  it("denies when user lacks the action bit with 403 JSON", async () => {
    const req = {
      originalUrl: "/api/posts",
      session: { user: { username: "alice", role: "editor", perms: { posts: Posts.actions.view.mask } } },
      headers: { accept: "application/json" },
    };
    const { res } = await callMiddleware(checkPermission(Posts.actions.delete), req);
    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({ success: false });
  });

  it("names the required permission in the 403 JSON payload", async () => {
    const req = {
      originalUrl: "/api/posts",
      session: { user: { username: "alice", role: "editor", perms: {} } },
      headers: { accept: "application/json" },
    };
    const { res } = await callMiddleware(checkPermission(Posts.actions.delete), req);
    expect(res.statusCode).toBe(403);
    expect(res.body.requiredPermission).toBe("posts:delete");
    expect(res.body.message).toContain("posts:delete");
  });

  it("names the required permission in the rendered 403 page", async () => {
    const req = {
      originalUrl: "/dashboard",
      session: { user: { username: "alice", role: "editor", perms: {} } },
      headers: { accept: "text/html" },
    };
    const { res } = await callMiddleware(checkPermission(Posts.actions.edit), req);
    expect(res.statusCode).toBe(403);
    expect(res.rendered.message).toContain("posts:edit");
  });

  it("SuperAdmin bypasses checkPermission unconditionally", async () => {
    const req = {
      originalUrl: "/api/posts",
      session: { user: { username: "root", role: "superadmin" } },
      headers: { accept: "application/json" },
    };
    const { ok } = await callMiddleware(checkPermission(Posts.actions.delete), req);
    expect(ok).toBe(true);
  });

  it("returns 401 when user is not authenticated", async () => {
    const req = { originalUrl: "/api/posts", session: {}, headers: { accept: "application/json" } };
    const { res } = await callMiddleware(checkPermission(Posts.actions.delete), req);
    expect(res.statusCode).toBe(401);
  });
});

describe("checkRolePermission", () => {
  it("allows matching role", async () => {
    const req = {
      originalUrl: "/dashboard/admin",
      session: { user: { username: "alice", role: "admin" } },
      headers: { accept: "application/json" },
    };
    const { ok } = await callMiddleware(checkRolePermission("admin"), req);
    expect(ok).toBe(true);
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
  });

  it("names multiple acceptable roles when specified", async () => {
    const req = {
      originalUrl: "/dashboard/admin",
      session: { user: { username: "alice", role: "guest" } },
      headers: { accept: "application/json" },
    };
    const { res } = await callMiddleware(checkRolePermission(["manager", "editor"]), req);
    expect(res.statusCode).toBe(403);
    expect(res.body.requiredRole).toEqual(["manager", "editor"]);
  });

  it("blocks user when notAllowed role matches", async () => {
    const req = {
      originalUrl: "/dashboard",
      session: { user: { username: "guest", role: "guest" } },
      headers: { accept: "application/json" },
    };
    const { res } = await callMiddleware(checkRolePermission("any", "guest"), req);
    expect(res.statusCode).toBe(403);
    expect(res.body.notAllowedRole).toBe("guest");
  });
});
