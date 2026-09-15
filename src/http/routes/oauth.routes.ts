/**
 * MBKAuthe OAuth Routes (Express Adapter)
 * Powered by Provider-Neutral OAuth & OIDC Engine
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import express, { Router } from "express";
import { mbkautheVar } from "../../config/index.js";
import { createLogger } from "../../utils/logger.js";
import { OAuthFlowService } from "../../oauth/OAuthFlowService.js";
import { loadOAuthProvidersFromConfig } from "../../oauth/providers/loader.js";
import { createOAuthRouter } from "../../express/oauth.router.js";

const router = express.Router();
const logOAuth = createLogger("oauth");

// Setup default flow service with providers auto-loaded from OAUTH_PROVIDERS config
const configuredProviders = loadOAuthProvidersFromConfig(mbkautheVar.OAUTH_PROVIDERS || mbkautheVar.oauth_providers);

const defaultFlowService = new OAuthFlowService({
  providers: configuredProviders,
  appName: mbkautheVar.APP_NAME || "mbkauthe",
});

const enabledProvidersList = defaultFlowService.listProviders().map((p) => p.name);
if (enabledProvidersList.length > 0) {
  logOAuth(`Social providers: ${enabledProvidersList.join(", ")}`);
}

// Attach nested modern OAuth router at /oauth
router.use("/oauth", createOAuthRouter(defaultFlowService));

export const oauthRouter = router;
export { defaultFlowService };
export default router;
