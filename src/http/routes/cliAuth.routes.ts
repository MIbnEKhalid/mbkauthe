import express from "express";
import rateLimit from "express-rate-limit";
import { sessRole } from "../middleware/authMiddleware.js";
import { renderPage } from "../response/formatters.js";
import { cliAuthService } from "../../services/CliAuthService.js";
import { mbkautheVar } from "../../config/env.js";
import { MbkAuthError } from "../../core/errors/MbkAuthError.js";
import { ErrorCodes } from "../../core/errors/catalog.js";

const router = express.Router();

const createCliLimit = (max: number, windowMs = 60 * 1000) =>
  rateLimit({
    windowMs,
    max,
    message: { success: false, message: "Too many requests, please try again later" } as any,
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false, trustProxy: false },
    keyGenerator: (req) => req.ip || (req.socket?.remoteAddress) || "unknown",
  });

const deviceRequestLimit = createCliLimit(20);
const devicePollLimit = createCliLimit(60);
const deviceApproveLimit = createCliLimit(30);

function getBaseUrl(req: express.Request): string {
  if (mbkautheVar.CLI_AUTH_BASE_URL) return String(mbkautheVar.CLI_AUTH_BASE_URL).replace(/\/+$/, "");
  if (mbkautheVar.IS_DEPLOYED === "true" && mbkautheVar.DOMAIN) return `https://${mbkautheVar.DOMAIN}`;
  return `${req.protocol || "http"}://${req.get("host") || "localhost"}`;
}

const renderCliError = (res: express.Response, req: express.Request, message: string) =>
  renderPage(req, res, "cli/device-approval.hbs", false, {
    pagename: "Approve CLI Login",
    pageTitle: "Approve CLI Login",
    status: "notfound",
    error: message,
  });

router.post("/api/cli/device", deviceRequestLimit, async (req, res) => {
  try {
    const { client_name, profile_id, profile_key } = req.body || {};
    const result = await cliAuthService.initiate({
      clientName: client_name,
      profileId: profile_id,
      profileKey: profile_key,
      baseUrl: getBaseUrl(req),
    });
    return res.status(201).json(result);
  } catch (err: any) {
    if (err instanceof MbkAuthError) {
      const message = typeof err.details === "string" ? err.details : err.message;
      return res.status(err.statusCode).json({ success: false, message });
    }
    console.error("Error creating CLI auth session:", err);
    return res.status(500).json({ success: false, message: "Failed to start CLI login" });
  }
});

router.get("/mbkauthe/cli/device/:user_code", sessRole("any"), async (req, res) => {
  try {
    const rawUserCode = Array.isArray(req.params.user_code) ? req.params.user_code[0] : req.params.user_code;
    const { session, profile, user_code, expires_in_seconds } = await cliAuthService.getSessionByUserCode(String(rawUserCode || ""));

    return renderPage(req, res, "cli/device-approval.hbs", false, {
      pagename: "Approve CLI Login",
      pageTitle: "Approve CLI Login",
      ogUrl: `/mbkauthe/cli/device/${user_code}`,
      user_code,
      status: session.status,
      client_name: session.client_name,
      profile: profile ? {
        name: profile.name,
        permissions: profile.permissions ?? [],
        expires_in_days: profile.expires_in_days,
      } : null,
      expires_in_seconds,
      username: (req as any).session.user.username,
    });
  } catch (err: any) {
    if (err instanceof MbkAuthError) {
      return renderCliError(res, req, err.message);
    }
    console.error("Error rendering CLI approval page:", err);
    return renderCliError(res, req, "Something went wrong while loading this login request.");
  }
});

router.post("/api/cli/device/approve", deviceApproveLimit, sessRole("any"), async (req, res) => {
  try {
    const { user_code, action } = req.body || {};
    if (!user_code || typeof user_code !== "string") {
      return res.status(400).json({ success: false, message: "user_code is required" });
    }

    if (action === "deny") {
      const denied = await cliAuthService.deny(user_code);
      if (!denied) return res.status(404).json({ success: false, message: "Login request not found" });
      return res.json({ success: true, status: "denied", message: "Login request denied" });
    }

    if (action !== "approve") {
      return res.status(400).json({ success: false, message: "Invalid action. Use 'approve' or 'deny'." });
    }

    const { username, role } = (req as any).session.user;
    await cliAuthService.approve(user_code, username, { role });
    return res.json({ success: true, status: "approved", message: "Login approved. The CLI will receive the token momentarily." });
  } catch (err: any) {
    if (err instanceof MbkAuthError) {
      const responsePayload: any = { success: false, message: err.message };
      if ((err as any).status) {
        responsePayload.status = (err as any).status;
      }
      return res.status(err.statusCode).json(responsePayload);
    }
    console.error("Error approving CLI login:", err);
    return res.status(500).json({ success: false, message: "Failed to approve login" });
  }
});

router.post("/api/cli/device/token", devicePollLimit, async (req, res) => {
  try {
    const { device_code } = req.body || {};
    const result = await cliAuthService.poll(device_code);
    return res.json(result);
  } catch (err: any) {
    if (err instanceof MbkAuthError) {
      const status = (err.errorCode === ErrorCodes.RESOURCE_NOT_FOUND) ? "invalid" : "error";
      return res.status(err.statusCode).json({ success: false, status, message: err.message });
    }
    console.error("Error polling CLI login:", err);
    return res.status(500).json({ success: false, message: "Failed to poll login" });
  }
});

export const cliAuthRouter = router;
export default router;

