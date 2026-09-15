/**
 * Express Adapter Router for Provider-Neutral OAuth & OIDC
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import express, { Router, type Request, type Response, type NextFunction } from "express";
import rateLimit from "express-rate-limit";
import { OAuthFlowService, oAuthFlowService } from "../oauth/OAuthFlowService.js";
import { completeLoginProcess } from "../http/session/authFlow.js";
import { sanitizeRelativeRedirect, isSafeRelativeRedirect } from "../http/utils/redirect.js";
import { renderError, sendSuccess, sendError } from "../http/response/formatters.js";
import { isJsonRequest } from "../http/response/contentNegotiation.js";
import { createLogger } from "../utils/logger.js";
import { mbkautheVar } from "../config/index.js";

import { resolveConfigSource } from "../oauth/providers/loader.js";

const logOAuth = createLogger("mbkauthe:express-oauth");

export interface OAuthRouterOptions {
  flowService?: OAuthFlowService;
  basePath?: string;
  defaultRedirectUrl?: string;
  rateLimitMax?: number;
  rateLimitWindowMs?: number;
}

export function createOAuthRouter(
  customService?: OAuthFlowService,
  options: OAuthRouterOptions = {}
): Router {
  const router = express.Router();
  const service = customService || options.flowService || oAuthFlowService;
  const defaultRedirect = options.defaultRedirectUrl || mbkautheVar.LOGIN_REDIRECT_URL || "/dashboard";

  const limiter = rateLimit({
    windowMs: options.rateLimitWindowMs || 5 * 60 * 1000,
    max: options.rateLimitMax || 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: "Too many OAuth requests, please try again later" },
    validate: { xForwardedForHeader: false, trustProxy: false },
    keyGenerator: (req) => req.ip || (req.socket?.remoteAddress) || "unknown",
  });

  // Helper to build callback URL for a provider
  const getCallbackUrl = (req: Request, providerId: string): string => {
    const protocol = req.headers["x-forwarded-proto"] || req.protocol || "http";
    const host = req.headers["x-forwarded-host"] || req.get("host") || "localhost";
    const baseUrl = `${protocol}://${host}`;

    // Check if provider has a custom callback URL configured in OAUTH_PROVIDERS
    const providerConfig = resolveConfigSource() || {};
    const normId = providerId.toLowerCase();
    for (const [k, v] of Object.entries(providerConfig)) {
      if (k.toLowerCase() === normId && v && typeof v === "object") {
        const customCallback = (v as any).redirect_uri || (v as any).redirectUri || (v as any).callback_url || (v as any).callbackUrl;
        if (customCallback && typeof customCallback === "string" && customCallback.trim()) {
          const trimmed = customCallback.trim();
          if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            return trimmed;
          }
          return `${baseUrl}${trimmed.startsWith("/") ? "" : "/"}${trimmed}`;
        }
      }
    }

    const mountPath = req.baseUrl || "";
    return `${baseUrl}${mountPath}/${providerId}/callback`;
  };

  /**
   * Helper to handle responses according to content negotiation (JSON vs HTML redirect)
   */
  const handleFlowResult = async (req: Request, res: Response, result: any, providerId: string) => {
    const { user, profile, returnTo, action } = result;

    if (action === "link") {
      if (isJsonRequest(req)) {
        return sendSuccess(res, {
          action: "link",
          message: `${providerId} account successfully linked.`,
          account: result.account,
        });
      }
      const redirectUrl = returnTo && isSafeRelativeRedirect(returnTo) ? returnTo : "/settings";
      return res.redirect(redirectUrl);
    }

    // Login Action: create session
    const is2FaEnabled = String(mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLowerCase() === "true" && user.is_enabled;

    if (is2FaEnabled) {
      logOAuth(`${providerId} login: 2FA required for user: ${user.username}`);
      (req as any).session.pre_auth_user = {
        user_id: user.user_id || undefined,
        username: user.username,
        role: user.role,
        allowed_apps: user.allowed_apps,
        full_name: user.full_name,
        image: user.image,
        login_method: providerId.toLowerCase(),
        redirect_url: returnTo || null,
      };

      if (isJsonRequest(req)) {
        return sendSuccess(res, {
          require_2fa: true,
          message: "2FA authentication required",
        });
      }
      return res.redirect("/mbkauthe/2fa");
    }

    // Intercept JSON response to handle HTML redirect cleanly
    const originalJson = res.json.bind(res);
    const originalStatus = res.status.bind(res);
    let statusCode = 200;

    res.status = function (code: number) {
      statusCode = code;
      return originalStatus(code);
    } as any;

    res.json = function (data: any) {
      res.json = originalJson;
      res.status = originalStatus;
      if (data?.success && statusCode === 200 && !isJsonRequest(req)) {
        const finalRedirect = returnTo && isSafeRelativeRedirect(returnTo) ? returnTo : defaultRedirect;
        logOAuth(`${providerId} login successful: Redirecting to ${finalRedirect}`);
        return res.redirect(finalRedirect);
      }
      return originalJson(data);
    } as any;

    const userForSession = {
      user_id: user.user_id || undefined,
      username: user.username,
      role: user.role,
      allowed_apps: user.allowed_apps,
      full_name: user.full_name,
      image: user.image,
    };

    return completeLoginProcess(req, res, userForSession, returnTo || null, providerId.toLowerCase());
  };

  /**
   * GET /providers
   * Lists available OAuth providers.
   */
  router.get("/providers", (req: Request, res: Response) => {
    return sendSuccess(res, { providers: service.listProviders() });
  });

  /**
   * GET /accounts
   * Lists linked OAuth accounts for current authenticated user.
   */
  router.get("/accounts", async (req: Request, res: Response) => {
    const user = (req as any).session?.user;
    if (!user || !user.username) {
      return sendError(res, "Authentication required to view linked accounts.", { statusCode: 401, code: "UNAUTHORIZED" });
    }

    try {
      const accounts = await service.listAccounts(user.username);
      return sendSuccess(res, { accounts });
    } catch (err: any) {
      return sendError(res, err.message, { statusCode: 500, code: "INTERNAL_ERROR" });
    }
  });

  /**
   * DELETE /accounts/:id
   * DELETE /:provider (Unlink)
   */
  router.delete(["/accounts/:id", "/:provider"], async (req: Request, res: Response) => {
    const user = (req as any).session?.user;
    if (!user || !user.username) {
      return sendError(res, "Authentication required to unlink accounts.", { statusCode: 401, code: "UNAUTHORIZED" });
    }

    const target = String(req.params.id || req.params.provider || "");

    try {
      const unlinked = await service.unlink(user.username, target);
      if (unlinked) {
        return sendSuccess(res, { message: `Account unlinked successfully.` });
      } else {
        return sendError(res, "Linked account not found.", { statusCode: 404, code: "NOT_FOUND" });
      }
    } catch (err: any) {
      return sendError(res, err.message, { statusCode: 500, code: "INTERNAL_ERROR" });
    }
  });

  /**
   * POST /:provider/link
   * Initiates account linking for authenticated user.
   */
  router.post(["/:provider/link", "/link/:provider"], limiter, async (req: Request, res: Response) => {
    const user = (req as any).session?.user;
    if (!user || !user.username) {
      return sendError(res, "Authentication required to link an OAuth account.", { statusCode: 401, code: "UNAUTHORIZED" });
    }

    const providerId = String(req.params.provider || "");
    const redirectUri = getCallbackUrl(req, providerId);
    const returnTo = sanitizeRelativeRedirect(req.query.redirect as string || req.body?.redirect || "/settings");

    try {
      const result = await service.begin(providerId, {
        redirectUri,
        returnTo,
        action: "link",
        userId: user.username,
      });

      if (isJsonRequest(req)) {
        return sendSuccess(res, result);
      }
      return res.redirect(result.authorizationUrl);
    } catch (err: any) {
      logOAuth(`Error initiating link for ${providerId}:`, err);
      return sendError(res, err, { statusCode: err.statusCode || 400, code: err.code || "OAUTH_LINK_ERROR" });
    }
  });

  /**
   * GET /:provider/begin
   * GET /:provider/login (alias)
   */
  router.get(["/:provider/begin", "/:provider/login"], limiter, async (req: Request, res: Response) => {
    const providerId = String(req.params.provider || "");
    const redirectUri = getCallbackUrl(req, providerId);
    const returnTo = sanitizeRelativeRedirect(req.query.redirect as string);

    try {
      const result = await service.begin(providerId, {
        redirectUri,
        returnTo: returnTo || undefined,
        action: "login",
      });

      if (isJsonRequest(req)) {
        return sendSuccess(res, result);
      }
      return res.redirect(result.authorizationUrl);
    } catch (err: any) {
      logOAuth(`Error initiating OAuth for ${providerId}:`, err);
      if (isJsonRequest(req)) {
        return sendError(res, err, { statusCode: err.statusCode || 400, code: err.code || "OAUTH_INIT_ERROR" });
      }
      return renderError(res, req, {
        code: err.statusCode || 400,
        error: "OAuth Initialization Failed",
        message: err.message || `Unable to start authentication with ${providerId}.`,
        page: "/mbkauthe/login",
        pagename: "Login",
      });
    }
  });

  /**
   * GET /:provider/callback
   * Completes OAuth flow.
   */
  router.get("/:provider/callback", limiter, async (req: Request, res: Response) => {
    const providerId = String(req.params.provider || "");
    const { code, state, error, error_description } = req.query as Record<string, string>;

    if (error) {
      logOAuth(`OAuth error from provider ${providerId}: ${error} - ${error_description}`);
      if (isJsonRequest(req)) {
        return sendError(res, error_description || "Authentication denied by provider", { statusCode: 400, code: error });
      }
      return renderError(res, req, {
        code: 400,
        error: "Authentication Error",
        message: error_description || `Provider returned an error: ${error}`,
        page: "/mbkauthe/login",
        pagename: "Login",
      });
    }

    if (!code || !state) {
      logOAuth(`Missing code or state in callback for ${providerId}`);
      if (isJsonRequest(req)) {
        return sendError(res, "Missing authorization code or state parameter.", { statusCode: 400, code: "INVALID_REQUEST" });
      }
      return renderError(res, req, {
        code: 400,
        error: "Invalid Request",
        message: "Missing authorization code or state parameter.",
        page: "/mbkauthe/login",
        pagename: "Login",
      });
    }

    const redirectUri = getCallbackUrl(req, providerId);

    try {
      const flowResult = await service.complete(providerId, {
        code,
        state,
        redirectUri,
        ip: req.ip || req.socket?.remoteAddress,
        userAgent: req.headers["user-agent"],
      });

      return await handleFlowResult(req, res, flowResult, providerId);
    } catch (err: any) {
      logOAuth(`OAuth callback failure for ${providerId}:`, err);

      if (isJsonRequest(req)) {
        return sendError(res, err, { statusCode: err.statusCode || 403, code: err.code || "OAUTH_CALLBACK_ERROR" });
      }

      const providerUpper = providerId.toUpperCase();
      let errorTitle = "Authentication Failed";
      let errorMsg = err.message || "An error occurred during authentication.";

      if (err.code === `${providerUpper}_NOT_LINKED` || err.code === "USER_NOT_FOUND") {
        errorTitle = `${providerId} Account Not Linked`;
        errorMsg = `Your ${providerId} account is not linked to any existing user in the system. Please log in with your credentials and connect this provider in your account settings.`;
      } else if (err.code === "ACCOUNT_INACTIVE") {
        errorTitle = "Account Inactive";
        errorMsg = "Your account has been deactivated. Please contact your administrator.";
      } else if (err.code === "NOT_AUTHORIZED") {
        errorTitle = "Not Authorized";
        errorMsg = `You are not authorized to access this application.`;
      }

      return renderError(res, req, {
        code: err.statusCode || 403,
        error: errorTitle,
        message: errorMsg,
        page: "/mbkauthe/login",
        pagename: "Login",
      });
    }
  });

  return router;
}

export const oauthRouter = createOAuthRouter();
export default oauthRouter;
