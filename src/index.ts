/**
 * MBKAuthe — Unified Authentication & Authorization Framework for MBK Ecosystem
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

// 1. Config & Environment
export { mbkautheVar, packageJson, appVersion, validateConfiguration, findValue, default as en } from "./config/index.js";
export {
  hashPassword,
  verifyPassword,
  hashApiToken,
  generatePrefixedToken,
  generateRandomHex,
  setPasswordPepper,
  getPasswordPepper,
} from "./config/security.js";
export {
  encryptSessionId,
  decryptSessionId,
  cachedCookieOptions,
  cachedClearCookieOptions,
  getCookieDomain,
  getCookieSecure,
  resolveCookieDomain,
  clearSessionCookies,
  generateDeviceToken,
  hashDeviceToken,
  getDeviceTokenCookieOptions,
  upsertAccountListCookie,
  readAccountListFromCookie,
  removeAccountFromCookie,
  clearAccountListCookie,
  isAllowedOriginHostname,
} from "./config/cookies.js";

// 2. Database Adapters, Dialects, Pools, and Schema
export { IDatabaseAdapter, QueryResult } from "./db/adapters/IDatabaseAdapter.js";
export { SqliteAdapter, SqliteAdapterOptions, SqlitePool } from "./db/adapters/SqliteAdapter.js";
export { PostgresAdapter } from "./db/adapters/PostgresAdapter.js";
export { IDialect } from "./db/dialects/IDialect.js";
export { postgresDialect } from "./db/dialects/PostgresDialect.js";
export { sqliteDialect } from "./db/dialects/SqliteDialect.js";
export { applySchema } from "./db/schema/applySchema.js";
export { translatePgToSqlite } from "./db/schema/ddlTranslate.js";
export { wrapPoolWithRetry, withQueryRetry, isRetryableDbError } from "./db/retry.js";
export { registerGracefulShutdown, closeAllConnections } from "./db/shutdown.js";
export { dblogin, dialect, dbType, runWithRequestContext, getRequestContext } from "./db/pool.js";
export { getQueryCount, getQueryLog, resetQueryCount, resetQueryLog, attachDevQueryLogger } from "./db/dbQueryLogger.js";

// 3. Database Repositories
export { BaseRepository, BaseRepositoryOptions } from "./db/repositories/BaseRepository.js";
export { AuthRepository, authRepository } from "./db/repositories/AuthRepository.js";
export { PermissionRepository, permissionRepository } from "./db/repositories/PermissionRepository.js";
export { ApiTokenRepository, apiTokenRepository } from "./db/repositories/ApiTokenRepository.js";
export { CliAuthSessionRepository, cliAuthSessionRepository } from "./db/repositories/CliAuthSessionRepository.js";

// 4. Permissions, Roles & Manifest
export {
  normalizePermission,
  resolvePermission,
  splitPermission,
  permissionMatches,
  matchPermission,
  compilePermissionPattern,
  normalizePermissions,
} from "./core/permissions/matcher.js";
export {
  RoleRegistry,
  defaultRoleRegistry,
  buildEffectivePermissions,
  intersectPermissions,
  hasPermission,
  GLOBAL_APP_KEY,
  GlobalRoles,
} from "./core/permissions/roleRegistry.js";
export {
  definePermissions,
  defineGlobalPermissions,
  GlobalPermissions,
  resolveAppKey,
  collectPermissions,
  collectRoles,
  MANIFEST_KEY,
  APP_KEY_KEY,
  ALL_PERMISSIONS_KEY,
  ROLES_KEY,
} from "./core/permissions/manifest.js";
export { syncAppPermissions } from "./core/permissions/registry.js";
export { attachSessionPermissions, hasNoSessionPermissions } from "./core/permissions/session.js";

// 5. Types
export * from "./core/types/index.js";

// 6. Errors
export { ErrorCodes, ErrorMessages, getErrorByCode, createErrorResponse, logError } from "./core/errors/catalog.js";
export { MbkAuthError } from "./core/errors/MbkAuthError.js";

// 7. UI, Handlebars & Response Helpers
export { commonHandlebarsHelpers, handlebarsHelpers } from "./ui/helpers/handlebarsHelpers.js";
export { isJsonRequest } from "./ui/response/contentNegotiation.js";
export {
  sendSuccess,
  sendError,
  renderPage,
  renderError,
  getUserContext,
  sanitizeErrorDetails,
} from "./ui/response/formatters.js";
export { createErrorHandler, createNotFoundHandler, proxycall } from "./ui/response/handlers.js";
export { isSafeFetchUrl } from "./ui/utils/urlSafety.js";
export { isSafeRelativeRedirect, sanitizeRelativeRedirect } from "./ui/utils/redirect.js";
export { isUserAuthorizedForApp } from "./ui/utils/appAccess.js";
export { createLogger, logDebug } from "./ui/utils/logger.js";
export { extractAuthorizationToken, timingSafeTokenMatch } from "./ui/utils/timingSafeToken.js";

// 8. HTTP & Express Middleware
export { SqliteSessionStore } from "./http/session/SqliteSessionStore.js";
export { sessionConfig, getSessionStore } from "./http/session/sessionConfig.js";
export {
  securityHeadersMiddleware,
  corsMiddleware,
  sessionRestorationMiddleware,
  sessionCookieSyncMiddleware,
  requestContextMiddleware,
} from "./http/middleware/security.js";
export {
  validateSession,
  validateApiSession,
  checkRolePermission,
  checkPermission,
  validateSessionAndRole,
  validateSessionAndPermission,
  authenticate,
  reloadSessionUser,
  strictValidateSession,
  strictValidateSessionAndRole,
  sessVal,
  sessRole,
  roleChk,
  strictSessVal,
  strictSessRole,
  permChk,
  sessPerm,
} from "./http/middleware/authMiddleware.js";

// 9. Express Routers
export { apiTokensRouter } from "./http/routes/apiToken.routes.js";
export { adminApiTokensRouter } from "./http/routes/adminApiToken.routes.js";
export { cliAuthRouter } from "./http/routes/cliAuth.routes.js";
export { authRouter } from "./http/routes/auth.routes.js";
export { oauthRouter } from "./http/routes/oauth.routes.js";
export { miscRouter, checkVersion } from "./http/routes/misc.routes.js";
export { dbLogsRouter } from "./http/routes/dbLogs.routes.js";

// 10. Legacy mbkauthShared compatibility object
import { commonHandlebarsHelpers } from "./ui/helpers/handlebarsHelpers.js";
import { isJsonRequest } from "./ui/response/contentNegotiation.js";
import { sendSuccess, sendError, renderPage, renderError, sanitizeErrorDetails } from "./ui/response/formatters.js";
import { createErrorHandler, createNotFoundHandler } from "./ui/response/handlers.js";

export const mbkauthShared = {
  commonHandlebarsHelpers,
  renderPage,
  renderError,
  createNotFoundHandler,
  createErrorHandler,
  sendSuccess,
  sendError,
  isJsonRequest,
  sanitizeErrorDetails,
};

// 11. Default export: Main Express application router
import mbkautheApp from "./http/app.js";
export default mbkautheApp;
