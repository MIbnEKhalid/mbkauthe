import speakeasy from "speakeasy";
import { AuthRepository, authRepository } from "../db/repositories/AuthRepository.js";
import { verifyPassword } from "../core/security/password.js";
import { authorizationService } from "../core/permissions/AuthorizationService.js";
import { AuthContext, createSessionAuthContext } from "../core/context/AuthContext.js";
import { MbkAuthError } from "../core/errors/MbkAuthError.js";
import { ErrorCodes } from "../core/errors/catalog.js";
import { emitAuthEvent } from "../core/events/index.js";
import { validateLoginDto, validateTotpDto, LoginDto, VerifyTotpDto } from "../core/validation/authDto.js";
import { AuthUser } from "../core/types/user.types.js";
import { createLogger } from "../utils/logger.js";
import { TokenEngine } from "../core/tokens/TokenEngine.js";

const debug = createLogger("mbkauthe:auth-service");

export interface LoginOptions {
  ip?: string;
  userAgent?: string;
  appKey?: string;
  maxSessions?: number;
  sessionDurationDays?: number;
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

export class AuthService {
  constructor(private repo: AuthRepository = authRepository) {}

  /**
   * Validates credentials and initiates login or 2FA challenge
   */
  async loginWithPassword(credentials: LoginDto, options: LoginOptions = {}): Promise<LoginResult> {
    const validated = validateLoginDto(credentials);
    const { username, password, rememberMe } = validated;
    const { ip, userAgent, appKey, maxSessions = 5, sessionDurationDays } = options;

    debug("Login attempt for username: %s (app: %s, ip: %s)", username, appKey, ip);

    const user = await this.repo.getUserWithTwoFA(username);
    if (!user || !user.password_hash) {
      emitAuthEvent("auth:login:failed", { username, reason: "USER_NOT_FOUND", ip, userAgent, appKey });
      throw new MbkAuthError(ErrorCodes.INCORRECT_PASSWORD, 401, "Invalid username or password");
    }

    const isValid = await verifyPassword(password, username, user.password_hash);
    if (!isValid) {
      emitAuthEvent("auth:login:failed", { username, reason: "INVALID_PASSWORD", ip, userAgent, appKey });
      throw new MbkAuthError(ErrorCodes.INCORRECT_PASSWORD, 401, "Invalid username or password");
    }

    if (user.is_active === false) {
      emitAuthEvent("auth:login:failed", { username, reason: "ACCOUNT_INACTIVE", ip, userAgent, appKey });
      throw new MbkAuthError(ErrorCodes.ACCOUNT_INACTIVE, 403, "User account is inactive");
    }

    if (!authorizationService.canAccessApp(user, appKey)) {
      emitAuthEvent("auth:login:failed", { username, reason: "APP_NOT_AUTHORIZED", ip, userAgent, appKey });
      throw new MbkAuthError(ErrorCodes.APP_NOT_AUTHORIZED, 403, "User not authorized for this application");
    }

    if (user.is_enabled) {
      return {
        requires2FA: true,
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
      meta: { ip, userAgent, appKey },
      maxSessions,
    });

    emitAuthEvent("auth:login:success", {
      userId: user.user_id || username,
      username,
      ip,
      userAgent,
      appKey,
      authMethod: "password",
    });

    const authContext = createSessionAuthContext(user, {
      id: sessionRow.id,
      expiresAt,
      ip,
      userAgent,
      appKey,
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

    const twoFaRecord = await this.repo.getTwoFASecret(user.username);
    const secret = twoFaRecord?.two_fa_secret || (twoFaRecord as any)?.secret;

    if (!secret) {
      throw new MbkAuthError(ErrorCodes.TWO_FA_NOT_CONFIGURED, 400, "Two-factor authentication is not configured for this user");
    }

    const verified = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
      window: 1,
    });

    if (!verified) {
      emitAuthEvent("auth:login:failed", { username: user.username, reason: "INVALID_2FA_TOKEN", ip, userAgent, appKey });
      throw new MbkAuthError(ErrorCodes.TWO_FA_INVALID_TOKEN, 401, "Invalid two-factor authentication code");
    }

    const days = sessionDurationDays || 1;
    const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

    const sessionRow = await this.repo.createAppSessionWithPruning({
      username: user.username,
      expiresAt,
      meta: { ip, userAgent, appKey },
      maxSessions,
    });

    emitAuthEvent("auth:login:success", {
      userId: user.user_id || user.username,
      username: user.username,
      ip,
      userAgent,
      appKey,
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
  async logoutSession(sessionId: string, userId?: string | number): Promise<void> {
    if (!sessionId) return;
    await this.repo.deleteAppSessionById(sessionId);
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
}

export const authService = new AuthService();
