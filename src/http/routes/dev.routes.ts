import express from "express";
import { renderError, renderPage } from "../response/formatters.js";
import { mbkautheVar } from "../../config/index.js";

const router = express.Router();

const renderDevError = (res: express.Response, req: express.Request, code: number, error: string, message: string, page = "/mbkauthe/login", details?: string) =>
  renderError(res, req, {
    code,
    error,
    message,
    details,
    pagename: "Home",
    page,
  });

// 2FA Preview
router.get("/2fa", (req, res) =>
  renderPage(req, res, "pages/2fa.handlebars", false, {
    pagename: "Two-Factor Authentication",
    page: "/home",
    DEVICE_TRUST_DURATION_DAYS: mbkautheVar.DEVICE_TRUST_DURATION_DAYS || 7,
  })
);

// Show Message Preview
router.get("/showmessage", (req, res) =>
  renderPage(req, res, "showmessage", false, {
    pagename: "Message Dialog",
    page: "/home",
  })
);

// Account Switch Preview
router.get(["/accounts", "/switch"], (req, res) =>
  renderPage(req, res, "pages/accountSwitch.handlebars", false, {
    pagename: "Switch Account",
    page: "/home",
    appName: mbkautheVar.APP_NAME || "portal",
  })
);

// Session Test Preview
router.get("/test", (req, res) =>
  renderPage(req, res, "pages/test.handlebars", false, {
    username: "dev.tester",
    full_name: "Developer Tester",
    role: "superadmin",
    user_id: "usr_dev_12345",
    session_id: "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
    session_id_short: "a1b2c3d4",
    profile_pic_url: encodeURIComponent("dev.tester"),
    display_name: "Developer Tester",
    initial: "D",
    allowed_apps: "portal, admin, db, deploy",
    session_expiry: new Date(Date.now() + 2 * 3600 * 1000).toISOString(),
    permissions: {
      allows: ["basic.access", "api:read", "api:write", "admin.access"],
      denies: ["billing.override"],
    },
    appName: mbkautheVar.APP_NAME || "portal",
  })
);

// Simulated HTTP Errors
router.get("/500", (req, res) =>
  renderDevError(res, req, 500, "Internal Server Error", "Simulated 500 Error", "/mbkauthe/login", "This is a simulated 500 error page for testing purposes.\nError: Simulated trace at devRoutes (dev.routes.ts:62:11)")
);
router.get("/404", (req, res) =>
  renderDevError(res, req, 404, "Page Not Found", "Simulated 404 Error", "/mbkauthe/login", "This is a simulated 404 error page for testing purposes.")
);
router.get("/403", (req, res) =>
  renderDevError(res, req, 403, "Forbidden", "Simulated 403 Error", "/mbkauthe/login", "This is a simulated 403 error page for testing purposes.")
);
router.get("/401", (req, res) =>
  renderDevError(res, req, 401, "Unauthorized", "Simulated 401 Error", "/mbkauthe/login", "This is a simulated 401 error page for testing purposes.")
);
router.get("/400", (req, res) =>
  renderDevError(res, req, 400, "Bad Request", "Simulated 400 Error", "/mbkauthe/login", "This is a simulated 400 error page for testing purposes.")
);

// CLI Device Approval Preview States
router.get("/device-approval", (req, res) => res.redirect("/dev/device-approval/pending"));

router.get("/device-approval/pending", (req, res) => {
  const sampleScopes = [
    "mbkbucket:read", "mbkbucket:write", "mbkbucket:delete", "mbkbucket:list", "mbkbucket:presign",
    "mbkdb:read", "mbkdb:write", "mbkdb:schema:modify", "mbkdb:migrate", "mbkdb:backup:create", "mbkdb:backup:restore",
    "mbkdeploy:read", "mbkdeploy:deploy", "mbkdeploy:rollback", "mbkdeploy:logs:read", "mbkdeploy:secrets:manage",
    "mbkauth:users:read", "mbkauth:users:write", "mbkauth:tokens:create", "mbkauth:tokens:revoke", "mbkauth:mfa:manage",
    "mbknetwork:dns:read", "mbknetwork:dns:write", "mbknetwork:ssl:renew", "mbknetwork:routes:manage",
    "mbkstorage:objects:read", "mbkstorage:objects:write", "mbkstorage:objects:delete", "mbkstorage:multipart:upload",
    "mbkmonitoring:metrics:read", "mbkmonitoring:alerts:write", "mbkmonitoring:traces:read", "mbkaudit:logs:export",
    "mbkorg:members:invite", "mbkorg:members:remove", "mbkorg:roles:manage", "mbkorg:billing:view"
  ];

  return renderPage(req, res, "cli/device-approval.handlebars", false, {
    status: "pending",
    client_name: "MBK CLI (macOS / arm64)",
    user_code: "WXYZ-9876",
    username: "ibnekhalid",
    expires_in_seconds: 300,
    profile: {
      name: "Developer CLI Profile",
      permissions: sampleScopes,
      expires_in_days: 30,
    },
    pagename: "Approve CLI Login",
    page: "/home",
  });
});

router.get("/device-approval/approved", (req, res) =>
  renderPage(req, res, "cli/device-approval.handlebars", false, {
    status: "approved",
    pagename: "Login Approved",
    page: "/home",
  })
);

router.get("/device-approval/completed", (req, res) =>
  renderPage(req, res, "cli/device-approval.handlebars", false, {
    status: "completed",
    pagename: "Token Delivered",
    page: "/home",
  })
);

router.get("/device-approval/denied", (req, res) =>
  renderPage(req, res, "cli/device-approval.handlebars", false, {
    status: "denied",
    pagename: "Login Denied",
    page: "/home",
  })
);

router.get("/device-approval/expired", (req, res) =>
  renderPage(req, res, "cli/device-approval.handlebars", false, {
    status: "expired",
    pagename: "Request Expired",
    page: "/home",
  })
);

router.get("/device-approval/notfound", (req, res) =>
  renderPage(req, res, "cli/device-approval.handlebars", false, {
    status: "notfound",
    error: "This login request could not be found or has already been processed.",
    pagename: "Request Not Found",
    page: "/home",
  })
);

router.get("/device-approval/unknown", (req, res) =>
  renderPage(req, res, "cli/device-approval.handlebars", false, {
    status: "unknown",
    pagename: "Unknown Request",
    page: "/home",
  })
);

export const devRouter = router;
export default router;
