import speakeasy from "speakeasy";
import { AuthRepository, authRepository } from "../db/repositories/AuthRepository.js";
import { verifyPassword } from "../core/security/password.js";
import { authorizationService } from "../core/permissions/AuthorizationService.js";
import { AuthContext, createSessionAuthContext } from "../core/context/AuthContext.js";
import { MbkAuthError } from "../core/errors/MbkAuthError.js";
import { ErrorCodes } from "../core/errors/catalog.js";
import { emitAuthEvent } from "../core/events/index.js";
import { validateLoginDto, validateTotpDto, LoginDto, VerifyTotpDto } from "../core/validation/authDto.js";
import { mbkautheVar, isProductionEnvironment } from "../config/index.js";
import { AuthUser, isLocalOnlyUser } from "../core/types/user.types.js";
import { createLogger } from "../utils/logger.js";
import { TokenEngine } from "../core/tokens/TokenEngine.js";

const debug = createLogger("mbkauthe:auth-service");

export interface LoginOptions {
  ip?: string;
  userAgent?: string;
  appKey?: string;
  maxSessions?: number;
  sessionDurationDays?: number;
  origin?: string;
  skipSessionCreation?: boolean;
}

export interface LoginResult {
  requires2FA: boolean;
  user?: AuthUser;
  authContext?: AuthContext;
  appSessionId?: string;
  expiresAt?: Date;
  tempToken?: string;
}

export interface Verify2FAResult {
  user: AuthUser;
  appSessionId: string;
  expiresAt: Date;
}

export interface DeviceAccount {
  session_id: string;
  username: string;
  full_name: string;
  image: string | null;
  role: string;
  origin: string | null;
  last_activity: string | null;
  expires_at: string | null;
  is_current: boolean;
}

export interface SwitchSessionResult {
  session_id: string;
  username: string;
  full_name: string;
  role: string;
}

export interface SessionValidityResult {
  valid: boolean;
  expiry: string | null;
}

export class AuthService {
  constructor(private repo: AuthRepository = authRepository) {}

  /**
   * Validates credentials and initiates login or 2FA challenge
   */
  async loginWithPassword(credentials: LoginDto, options: LoginOptions = {}): Promise<LoginResult> {
    const validated = validateLoginDto(credentials);
    const { username, password, rememberMe } = validated;
    const { ip, userAgent, appKey, maxSessions = 5, sessionDurationDays } = options;
    const targetAppKey = appKey || mbkautheVar.APP_NAME;

    debug("Login attempt for username: %s (app: %s, ip: %s)", username, targetAppKey, ip);

    const user = await this.repo.getUserWithTwoFA(username);
    if (!user || !user.password_hash) {
      emitAuthEvent("auth:login:failed", { username, reason: "USER_NOT_FOUND", ip, userAgent, appKey: targetAppKey });
      throw new MbkAuthError(ErrorCodes.INVALID_CREDENTIALS, 401, "Invalid username or password");
    }

    const isValid = await verifyPassword(password, username, user.password_hash);
    if (!isValid) {
      emitAuthEvent("auth:login:failed", { username, reason: "INVALID_PASSWORD", ip, userAgent, appKey: targetAppKey });
      throw new MbkAuthError(ErrorCodes.INCORRECT_PASSWORD, 401, "Invalid username or password");
    }

    if (user.is_active === false) {
      emitAuthEvent("auth:login:failed", { username, reason: "ACCOUNT_INACTIVE", ip, userAgent, appKey: targetAppKey });
      throw new MbkAuthError(ErrorCodes.ACCOUNT_INACTIVE, 403, "User account is inactive");
    }

    const isLocalOnly = isLocalOnlyUser(user.is_local_only);
    if (isLocalOnly && isProductionEnvironment()) {
      emitAuthEvent("auth:login:failed", { username, reason: "LOCAL_USER_PROD_RESTRICTED", ip, userAgent, appKey: targetAppKey });
      throw new MbkAuthError(ErrorCodes.LOCAL_USER_PROD_RESTRICTED, 403, "User account is restricted to local environments");
    }

    if (!authorizationService.canAccessApp(user, targetAppKey)) {
      emitAuthEvent("auth:login:failed", { username, reason: "APP_NOT_AUTHORIZED", ip, userAgent, appKey: targetAppKey });
      throw new MbkAuthError(ErrorCodes.APP_NOT_AUTHORIZED, 403, `You are not authorized to access ${targetAppKey}`);
    }

    const is2FaEnabled = String(mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLowerCase() === "true" && Boolean(user.is_enabled);
    if (is2FaEnabled) {
      return {
        requires2FA: true,
        user,
        authContext: createSessionAuthContext(user),
      };
    }

    if (options.skipSessionCreation) {
      return {
        requires2FA: false,
        user,
        authContext: createSessionAuthContext(user),
      };
    }

    // Determine session expiration
    const days = sessionDurationDays || (rememberMe ? 30 : 1);
    const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

    const sessionRow = await this.repo.createAppSessionWithPruning({
      username,
      expiresAt,
      meta: { ip, userAgent, appKey: targetAppKey, ...(options.origin ? { origin: options.origin, domain: options.origin } : {}) },
      maxSessions,
    });

    emitAuthEvent("auth:login:success", {
      userId: user.user_id || username,
      username,
      ip,
      userAgent,
      appKey: targetAppKey,
      authMethod: "password",
    });

    const authContext = createSessionAuthContext(user, {
      id: sessionRow.id,
      expiresAt,
      ip,
      userAgent,
      appKey: targetAppKey,
    });

    return {
      requires2FA: false,
      user,
      authContext,
      appSessionId: sessionRow.id,
      expiresAt,
    };
  }

  /**
   * Verifies a 2FA TOTP code and creates a session upon success
   */
  async verifyTwoFactor(dto: VerifyTotpDto, user: AuthUser, options: LoginOptions = {}): Promise<Verify2FAResult> {
    const validated = validateTotpDto(dto);
    const { token } = validated;
    const { ip, userAgent, appKey, maxSessions = 5, sessionDurationDays } = options;
    const targetAppKey = appKey || mbkautheVar.APP_NAME;

    const twoFaRecord = await this.repo.getTwoFASecret(user.username);
    const secret = twoFaRecord?.two_fa_secret || (twoFaRecord as any)?.secret;

    if (!secret) {
      throw new MbkAuthError(ErrorCodes.TWO_FA_NOT_CONFIGURED, 500, "Two-factor authentication is not configured for this user");
    }

    const verified = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
      window: 1,
    });

    if (!verified) {
      emitAuthEvent("auth:login:failed", { username: user.username, reason: "INVALID_2FA_TOKEN", ip, userAgent, appKey: targetAppKey });
      throw new MbkAuthError(ErrorCodes.TWO_FA_INVALID_TOKEN, 401, "Invalid two-factor authentication code");
    }

    if (options.skipSessionCreation) {
      return {
        user,
        appSessionId: "",
        expiresAt: new Date(),
      };
    }

    const days = sessionDurationDays || 1;
    const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

    const sessionRow = await this.repo.createAppSessionWithPruning({
      username: user.username,
      expiresAt,
      meta: { ip, userAgent, appKey: targetAppKey },
      maxSessions,
    });

    emitAuthEvent("auth:login:success", {
      userId: user.user_id || user.username,
      username: user.username,
      ip,
      userAgent,
      appKey: targetAppKey,
      authMethod: "2fa",
    });

    return {
      user,
      appSessionId: sessionRow.id,
      expiresAt,
    };
  }

  /**
   * Logs out a session by session ID
   */
  async logoutSession(sessionId?: string, userId?: string | number, options?: { sid?: string }): Promise<void> {
    const operations: Promise<any>[] = [];
    if (sessionId) {
      operations.push(this.repo.deleteAppSessionById(sessionId, "logout-delete-app-session"));
    }
    if (options?.sid) {
      operations.push(this.repo.deleteSessionBySid(options.sid, "logout-delete-session"));
    }
    await Promise.all(operations);
    emitAuthEvent("auth:logout", {
      sessionId,
      userId,
    });
  }

  /**
   * Dispatches account switched event
   */
  notifyAccountSwitched(toUserId: string | number, username: string, fromUserId?: string | number): void {
    emitAuthEvent("auth:account:switched", {
      fromUserId,
      toUserId,
      username,
    });
  }

  /**
   * Retrieves and validates all active accounts remembered for a specific device.
   * Cleans up expired/unauthorized sessions on the fly.
   */
  async listDeviceAccounts(
    deviceId: string,
    currentSessionId?: string,
    appKey?: string
  ): Promise<{ accounts: DeviceAccount[]; current_session_id?: string }> {
    if (!deviceId) return { accounts: [], current_session_id: currentSessionId };

    const targetAppKey = appKey || mbkautheVar.APP_NAME;
    const sessionRows: any[] = await this.repo.findSessionsByDeviceId(deviceId);
    const validated: DeviceAccount[] = [];

    for (const row of sessionRows) {
      const expired = row.expires_at && new Date(row.expires_at) <= new Date();
      const isLocalOnly = isLocalOnlyUser(row.is_local_only);
      const authorized = Boolean(
        row.is_active &&
        !(isLocalOnly && isProductionEnvironment()) &&
        (row.role === "superadmin" ||
          (Array.isArray(row.allowed_apps) &&
            row.allowed_apps.some((app: any) => app?.toLowerCase() === targetAppKey?.toLowerCase())))
      );

      if (expired || !authorized) {
        if (row.sid) {
          await this.repo.deleteAppSessionById(row.sid).catch(() => {});
        }
        continue;
      }

      let parsedMeta: any = {};
      if (typeof row.meta === "string") {
        try {
          parsedMeta = JSON.parse(row.meta);
        } catch {}
      } else if (row.meta && typeof row.meta === "object") {
        parsedMeta = row.meta;
      }

      validated.push({
        session_id: row.sid,
        username: row.username,
        full_name: row.full_name || row.username,
        image: row.image?.trim() ? row.image : null,
        role: row.role || "user",
        origin: parsedMeta.origin || null,
        last_activity: row.last_activity || null,
        expires_at: row.expires_at || null,
        is_current: Boolean(currentSessionId && row.sid === currentSessionId),
      });
    }

    return { accounts: validated, current_session_id: currentSessionId };
  }

  /**
   * Switches device active session to target session ID after validating access and activity
   */
  async switchDeviceSession(
    deviceId: string,
    targetSessionId: string,
    currentUserId?: string | number,
    appKey?: string
  ): Promise<SwitchSessionResult> {
    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!targetSessionId || typeof targetSessionId !== "string" || !UUID_REGEX.test(targetSessionId)) {
      throw new MbkAuthError(ErrorCodes.INVALID_TOKEN_FORMAT, 400, "Invalid session id");
    }

    const targetSession = await this.repo.findDeviceSession(deviceId, targetSessionId);
    if (!targetSession) {
      throw new MbkAuthError(ErrorCodes.SESSION_NOT_FOUND, 403, "Account not available on this device");
    }

    if (!targetSession.is_active) {
      throw new MbkAuthError(ErrorCodes.ACCOUNT_INACTIVE, 401, "Account is inactive");
    }

    const isLocalOnly = isLocalOnlyUser(targetSession.is_local_only);
    if (isLocalOnly && isProductionEnvironment()) {
      throw new MbkAuthError(ErrorCodes.LOCAL_USER_PROD_RESTRICTED, 403, "User account is restricted to local environments");
    }

    const targetAppKey = appKey || mbkautheVar.APP_NAME;
    if (targetSession.role !== "superadmin") {
      const allowed = targetSession.allowed_apps;
      if (!Array.isArray(allowed) || !allowed.some((app: any) => app?.toLowerCase() === targetAppKey?.toLowerCase())) {
        throw new MbkAuthError(ErrorCodes.APP_NOT_AUTHORIZED, 401, "You are not authorized to access this app");
      }
    }

    await this.repo.touchSessionActivity(targetSession.sid);

    this.notifyAccountSwitched(targetSession.user_id || targetSession.username, targetSession.username, currentUserId);

    return {
      session_id: targetSession.sid,
      username: targetSession.username,
      full_name: targetSession.full_name || targetSession.username,
      role: targetSession.role || "user",
    };
  }

  /**
   * Logs out a single device account session
   */
  async logoutDeviceAccount(deviceId: string, targetSessionId: string): Promise<boolean> {
    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!targetSessionId || typeof targetSessionId !== "string" || !UUID_REGEX.test(targetSessionId)) {
      throw new MbkAuthError(ErrorCodes.INVALID_TOKEN_FORMAT, 400, "Invalid session id");
    }

    const deleted = await this.repo.deleteDeviceSession(deviceId, targetSessionId);
    if (!deleted) {
      throw new MbkAuthError(ErrorCodes.SESSION_NOT_FOUND, 403, "Account not available on this device");
    }

    emitAuthEvent("auth:logout", { sessionId: targetSessionId });
    return true;
  }

  /**
   * Logs out all device sessions for a device
   */
  async logoutAllDeviceAccounts(deviceId: string): Promise<void> {
    await this.repo.deleteAllDeviceSessions(deviceId);
    emitAuthEvent("auth:logout", { allDevices: true });
  }

  /**
   * Validates a session by session ID and returns validity and expiry
   */
  async validateSession(sessionId: string, queryName: string = "validate-session"): Promise<SessionValidityResult> {
    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!sessionId || typeof sessionId !== "string" || !UUID_REGEX.test(sessionId)) {
      return { valid: false, expiry: null };
    }

    const row = await this.repo.getSessionValidationRow(sessionId, queryName);
    if (!row || (row.expires_at && new Date(row.expires_at) <= new Date()) || !row.is_active) {
      return { valid: false, expiry: null };
    }

    return {
      valid: true,
      expiry: row.expires_at ? new Date(row.expires_at).toISOString() : null,
    };
  }

  /**
   * Validates session with express session ID
   */
  async validateSessionWithSid(sessionId: string, sid?: string): Promise<SessionValidityResult> {
    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!sessionId || typeof sessionId !== "string" || !UUID_REGEX.test(sessionId)) {
      return { valid: false, expiry: null };
    }

    const row = await this.repo.getSessionValidity(sessionId, sid || "", "check-session-validity");
    if (!row || (row.expires_at && new Date(row.expires_at) <= new Date()) || !row.is_active) {
      return { valid: false, expiry: null };
    }

    const expiry_source = row.expires_at || (row as any).connect_expire || null;
    return {
      valid: true,
      expiry: expiry_source ? new Date(expiry_source).toISOString() : null,
    };
  }

  /**
   * Administrative bulk termination of all active sessions
   */
  async terminateAllSessions(): Promise<void> {
    await Promise.all([
      this.repo.deleteAllAppSessions("terminate-all-app-sessions"),
      this.repo.deleteActiveSessionStoreRows("terminate-all-db-sessions"),
    ]);
  }
}

export const authService = new AuthService();
