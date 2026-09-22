/**
 * MBKAuthe OAuth Routes (Express Adapter)
 * Powered by Provider-Neutral OAuth & OIDC Engine
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import express, { Router } from "express";
import { mbkautheVar } from "../../config/index.js";
import { createLogger } from "../../utils/logger.js";
import { oAuthFlowService as defaultFlowService } from "../../oauth/OAuthFlowService.js";
import { createOAuthRouter } from "../../express/oauth.router.js";
import { ensureSession } from "../middleware/security.js";

const router = express.Router();
router.use("/oauth", ensureSession);
const logOAuth = createLogger("oauth");

const enabledProvidersList = defaultFlowService.listProviders().map((p) => p.name);
if (enabledProvidersList.length > 0) {
  logOAuth(`Social providers: ${enabledProvidersList.join(", ")}`);
}

// Attach nested modern OAuth router at /oauth
router.use("/oauth", createOAuthRouter(defaultFlowService));

export const oauthRouter = router;
export { defaultFlowService };
export default router;
