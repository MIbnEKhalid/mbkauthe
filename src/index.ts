/**
 * MBKAuthe — Unified Authentication & Authorization Framework for MBK Ecosystem
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

// 1. Config & Environment
export { mbkautheVar, packageJson, appVersion, validateConfiguration, checkConfigurationStatus, findValue, isProductionEnvironment, default as en } from "./config/index.js";
export {
  hashPassword,
  verifyPassword,
  hashApiToken,
  generatePrefixedToken,
  generateRandomHex,
  setPasswordPepper,
  getPasswordPepper,
} from "./config/security.js";
export * from "./core/security/index.js";
export {
  encryptSessionId,
  decryptSessionId,
  getCookieOptions,
  getClearCookieOptions,
  getCookieDomain,
  getCookieSecure,
  resolveCookieDomain,
  isAllowedOriginHostname,
  clearSessionCookies,
  DEVICE_ID_COOKIE,
  getOrCreateDeviceId,
} from "./config/cookies.js";
export { extractRequestOrigin, completeLoginProcess } from "./http/session/authFlow.js";

// 2. Database Adapters, Dialects, Pools, and Schema
export { type IDatabaseAdapter, type QueryResult } from "./db/adapters/IDatabaseAdapter.js";
export { SqliteAdapter, type SqliteAdapterOptions, SqlitePool } from "./db/adapters/SqliteAdapter.js";
export { PostgresAdapter } from "./db/adapters/PostgresAdapter.js";
export { type IDialect } from "./db/dialects/IDialect.js";
export { postgresDialect } from "./db/dialects/PostgresDialect.js";
export { sqliteDialect } from "./db/dialects/SqliteDialect.js";
export { applySchema } from "./db/schema/applySchema.js";
export { translatePgToSqlite } from "./db/schema/ddlTranslate.js";
export { wrapPoolWithRetry, withQueryRetry, isRetryableDbError } from "./db/retry.js";
export { registerGracefulShutdown, closeAllConnections } from "./db/shutdown.js";
export { dblogin, dialect, dbType, runWithRequestContext, getRequestContext } from "./db/pool.js";
export { getQueryCount, getQueryLog, resetQueryCount, resetQueryLog, attachDevQueryLogger } from "./db/dbQueryLogger.js";

// 3. Database Repositories
export { BaseRepository, type BaseRepositoryOptions } from "./db/repositories/BaseRepository.js";
export { UserRepository, userRepository } from "./db/repositories/UserRepository.js";
export { SessionRepository, sessionRepository } from "./db/repositories/SessionRepository.js";
export { PasskeyRepository, passkeyRepository, type PasskeyRow, type CreatePasskeyParams } from "./db/repositories/PasskeyRepository.js";
export { AuthRepository, authRepository } from "./db/repositories/AuthRepository.js";
export { PermissionRepository, permissionRepository } from "./db/repositories/PermissionRepository.js";
export { ApiTokenRepository, apiTokenRepository } from "./db/repositories/ApiTokenRepository.js";
export { CliAuthSessionRepository, cliAuthSessionRepository } from "./db/repositories/CliAuthSessionRepository.js";
export { OAuthAccountRepository, oAuthAccountRepository } from "./db/repositories/OAuthAccountRepository.js";


// 4. Domain Events & Token Engine
export {
  authEvents,
  AuthEventEmitter,
  emitAuthEvent,
  type AuthLoginSuccessEvent,
  type AuthLoginFailedEvent,
  type AuthLogoutEvent,
  type AuthTokenCreatedEvent,
  type AuthTokenRevokedEvent,
  type AuthAccountSwitchedEvent,
  type AuthCliApprovedEvent,
  type AuthCliDeniedEvent,
  type AuthEventMap,
  type AuthEventName,
  type AuthEventListener,
} from "./core/events/index.js";
export {
  TokenEngine,
  TOKEN_PREFIXES,
  type TokenType,
  type ParsedToken,
} from "./core/tokens/index.js";
export {
  validateLoginDto,
  validateTotpDto,
  validateCreateApiTokenDto,
  validateCliDeviceCodeDto,
  type LoginDto,
  type VerifyTotpDto,
  type CreateApiTokenDto,
  type CliDeviceCodeDto,
} from "./core/validation/index.js";

// 5. Service Layer
export {
  AuthService,
  authService,
  type LoginOptions,
  type LoginResult,
  type DeviceAccount,
  type SwitchSessionResult,
  type SessionValidityResult,
  PasskeyService,
  passkeyService,
  type PasskeyServiceOptions,
  ApiTokenService,
  apiTokenService,
  type CreateTokenResult,
  type CreateTokenOptions,
  type VerifyTokenResult,
  CliAuthService,
  cliAuthService,
  type InitiateCliAuthParams,
  type CliAuthInitiateResult,
  type PollCliAuthResult,
  OAuthFlowService,
  oAuthFlowService,
  getDefaultOAuthFlowService,
  syncAppPermissions,
  type SyncAppPermissionsOptions,
  type SyncResult,
} from "./services/index.js";


// 5b. OAuth & OIDC Provider-Neutral Engine & createAuth DI Factory
export * from "./oauth/index.js";
export { createAuth, MbkAuthInstance, type AuthConfig, type OAuthConfig, type AuthRepositoriesConfig } from "./core/createAuth.js";


// 6. Diagnostics & Observability
export { getAuthHealthReport, AuthHealthStatus } from "./diagnostics/index.js";

// 7. Permissions, Roles, Authorization & Manifest
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
  AuthorizationService,
  authorizationService,
  type PolicyFn,
} from "./core/permissions/AuthorizationService.js";
export {
  AuthContext,
  createAuthContext,
  createAnonymousContext,
  createSessionAuthContext,
  createTokenAuthContext,
  principalFromUser,
  type AuthPrincipal,
  type AuthSessionInfo,
  type AuthTokenInfo,
  type AuthMethod,
  type AuthContextOptions,
} from "./core/context/AuthContext.js";
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
export { attachSessionPermissions, hasNoSessionPermissions, SUPERADMIN_PERMISSIONS } from "./http/session/sessionPermissions.js";

// 8. Types
export * from "./core/types/index.js";

// 9. Errors
export { ErrorCodes, ErrorMessages, getErrorByCode, createErrorResponse, logError } from "./core/errors/catalog.js";
export { MbkAuthError } from "./core/errors/MbkAuthError.js";

// 10. HTTP Response, UI & Helpers
export { commonHandlebarsHelpers, handlebarsHelpers } from "./ui/helpers/handlebarsHelpers.js";
export { isJsonRequest } from "./http/response/contentNegotiation.js";
export { sendSuccess, sendError, renderPage, renderError, getUserContext, sanitizeErrorDetails } from "./http/response/formatters.js";
export { createErrorHandler, createNotFoundHandler, proxycall } from "./http/response/handlers.js";
export { isSafeFetchUrl } from "./http/utils/urlSafety.js";
export { isSafeRelativeRedirect, sanitizeRelativeRedirect } from "./http/utils/redirect.js";
export { isUserAuthorizedForApp } from "./http/utils/appAccess.js";
export { createLogger, logDebug } from "./utils/logger.js";
export { extractAuthorizationToken, timingSafeTokenMatch } from "./core/tokens/index.js";

// 11. HTTP & Express Middleware
export { SqliteSessionStore } from "./http/session/SqliteSessionStore.js";
export { sessionConfig, getSessionStore, getSessionMiddleware, hasSessionCookie } from "./http/session/sessionConfig.js";
export {
  securityHeadersMiddleware,
  corsMiddleware,
  ensureSession,
  ensureSessionAsync,
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

// 12. Express Routers & App Factory
export { apiTokensRouter } from "./http/routes/apiToken.routes.js";
export { adminApiTokensRouter } from "./http/routes/adminApiToken.routes.js";
export { cliAuthRouter } from "./http/routes/cliAuth.routes.js";
export { authRouter } from "./http/routes/auth.routes.js";
export { oauthRouter } from "./http/routes/oauth.routes.js";
export { miscRouter, checkVersion } from "./http/routes/misc.routes.js";
export { dbLogsRouter } from "./http/routes/dbLogs.routes.js";
export { devRouter } from "./http/routes/dev.routes.js";
export { createMbkautheApp, mbkautheApp } from "./http/app.js";

// 13. Legacy mbkauthShared compatibility object
import { commonHandlebarsHelpers } from "./ui/helpers/handlebarsHelpers.js";
import { isJsonRequest } from "./http/response/contentNegotiation.js";
import { sendSuccess, sendError, renderPage, renderError, sanitizeErrorDetails } from "./http/response/formatters.js";
import { createErrorHandler, createNotFoundHandler } from "./http/response/handlers.js";

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

// 14. Default export: Main Express application router
import defaultApp from "./http/app.js";
export default defaultApp;
