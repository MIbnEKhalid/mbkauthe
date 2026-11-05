import crypto from "node:crypto";
import { AuthChallengeRepository, authChallengeRepository } from "../db/repositories/AuthChallengeRepository.js";
import { UserRepository, userRepository } from "../db/repositories/UserRepository.js";
import { hashPassword } from "../core/security/password.js";
import { emitAuthEvent } from "../core/events/index.js";
import { mbkautheVar } from "../config/index.js";
import { MbkAuthError } from "../core/errors/MbkAuthError.js";
import { ErrorCodes } from "../core/errors/catalog.js";

export interface AuthEmailProvider {
  sendResetLink(email: string, username: string, resetLink: string): Promise<void>;
  sendOtpCode(email: string, username: string, otpCode: string, expiresMinutes: number): Promise<void>;
}

let activeEmailProvider: AuthEmailProvider | null = null;

export function setAuthEmailProvider(provider: AuthEmailProvider | null): void {
  activeEmailProvider = provider;
}

export function getAuthEmailProvider(): AuthEmailProvider | null {
  return activeEmailProvider;
}

export function hashChallengeToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export class AuthResetService {
  constructor(
    private challengeRepo: AuthChallengeRepository = authChallengeRepository,
    private userRepo: UserRepository = userRepository
  ) {}

  /**
   * Request a password reset for a given username or email.
   * Generates a single-use token/code and dispatches it via registered email provider or event.
   */
  async requestPasswordReset(
    identifier: string,
    options: { origin?: string; challengeType?: "reset_link" | "otp_code" } = {}
  ): Promise<{ success: boolean; message: string }> {
    const trimmed = typeof identifier === "string" ? identifier.trim() : "";
    if (!trimmed) {
      return {
        success: true,
        message: "If an account matches the provided identifier, instructions have been sent to the associated email.",
      };
    }

    const user = await this.userRepo.findByUsernameOrEmail(trimmed);
    if (!user || !user.username) {
      return {
        success: true,
        message: "If an account matches the provided identifier, instructions have been sent to the associated email.",
      };
    }

    const username = user.username;
    const email = user.email;

    // Rate-limiting check
    const recentAttempts = await this.challengeRepo.getRecentAttemptCount(username, 60);
    if (recentAttempts >= 5) {
      throw new MbkAuthError(
        ErrorCodes.RATE_LIMIT_EXCEEDED,
        429,
        "Too many reset requests. Please wait a while before requesting again."
      );
    }

    const challengeType = options.challengeType || "reset_link";
    const rawToken = challengeType === "otp_code"
      ? crypto.randomInt(100000, 999999).toString()
      : crypto.randomBytes(32).toString("hex");

    const tokenHash = hashChallengeToken(rawToken);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes TTL

    await this.challengeRepo.createChallenge({
      username,
      challenge_type: challengeType,
      token_hash: tokenHash,
      expires_at: expiresAt,
      max_attempts: 5,
    });

    const baseUrl = options.origin || mbkautheVar.BASE_URL || "";
    const resetLink = `${baseUrl}/mbkauthe/reset-password?token=${rawToken}&username=${encodeURIComponent(username)}`;

    if (email && activeEmailProvider) {
      try {
        if (challengeType === "otp_code") {
          await activeEmailProvider.sendOtpCode(email, username, rawToken, 15);
        } else {
          await activeEmailProvider.sendResetLink(email, username, resetLink);
        }
      } catch (emailErr) {
        console.error("[mbkauthe] Failed to dispatch reset email via provider:", emailErr);
      }
    }

    emitAuthEvent("auth:password:reset-requested" as any, {
      username,
      email: email || null,
      challengeType,
      resetLink,
    });

    return {
      success: true,
      message: "If an account matches the provided identifier, instructions have been sent to the associated email.",
    };
  }

  /**
   * Validates a password reset token or OTP code without consuming it.
   */
  async validateResetToken(
    username: string,
    tokenOrOtp: string
  ): Promise<{ valid: boolean; message?: string }> {
    if (!username || !tokenOrOtp) return { valid: false, message: "Missing token or username" };

    const challenge = await this.challengeRepo.findActiveChallenge(username);
    if (!challenge) {
      return { valid: false, message: "Invalid or expired challenge" };
    }

    if (new Date(challenge.expires_at).getTime() < Date.now()) {
      return { valid: false, message: "Challenge has expired" };
    }

    if (challenge.attempts >= challenge.max_attempts) {
      return { valid: false, message: "Maximum attempts exceeded. Please request a new one." };
    }

    const inputHash = hashChallengeToken(tokenOrOtp);
    const expectedBuf = Buffer.from(challenge.token_hash, "hex");
    const actualBuf = Buffer.from(inputHash, "hex");

    if (expectedBuf.length !== actualBuf.length || !crypto.timingSafeEqual(expectedBuf, actualBuf)) {
      await this.challengeRepo.incrementAttempts(challenge.id);
      return { valid: false, message: "Invalid token or code" };
    }

    return { valid: true };
  }

  /**
   * Consumes challenge and updates user's password.
   */
  async resetPassword(
    username: string,
    tokenOrOtp: string,
    newPassword: string
  ): Promise<{ success: boolean; message: string }> {
    if (!newPassword || newPassword.length < 8) {
      throw new MbkAuthError(
        ErrorCodes.INVALID_PASSWORD_LENGTH,
        400,
        "Password must be at least 8 characters long."
      );
    }

    const validation = await this.validateResetToken(username, tokenOrOtp);
    if (!validation.valid) {
      throw new MbkAuthError(
        ErrorCodes.INVALID_CREDENTIALS,
        400,
        validation.message || "Invalid or expired reset token."
      );
    }

    const challenge = await this.challengeRepo.findActiveChallenge(username);
    if (challenge) {
      await this.challengeRepo.markConsumed(challenge.id);
    }

    const passwordHash = hashPassword(newPassword, username);
    await this.userRepo.updatePassword(username, passwordHash);
    await this.userRepo.setMustChangePassword(username, false);
    await this.challengeRepo.clearChallengesForUser(username);

    emitAuthEvent("auth:password:changed" as any, {
      username,
      method: "challenge_reset",
    });

    return { success: true, message: "Password reset successful. You can now log in." };
  }

  /**
   * Generates an administrator-issued OTP for initial activation or emergency access.
   * Sets user's password to the OTP hash and flags must_change_password = true.
   */
  async generateAdminOtp(
    username: string,
    expiryHours: number = 168
  ): Promise<{ rawOTP: string; expiresAt: string }> {
    const user = await this.userRepo.getUserByUsername(username);
    if (!user) {
      throw new MbkAuthError(ErrorCodes.USER_NOT_FOUND, 404, "User not found");
    }

    const rawOTP = crypto.randomBytes(4).toString("hex").toUpperCase(); // 8-char uppercase hex
    const otpHash = hashChallengeToken(rawOTP);
    const expiresAt = new Date(Date.now() + expiryHours * 60 * 60 * 1000);

    // Save unified challenge
    await this.challengeRepo.createChallenge({
      username,
      challenge_type: "admin_otp",
      token_hash: otpHash,
      expires_at: expiresAt,
      max_attempts: 10,
    });

    // Update password_hash to temporary OTP hash so user can log in with OTP
    const userPasswordHash = hashPassword(rawOTP, username);
    await this.userRepo.updatePassword(username, userPasswordHash);
    await this.userRepo.setMustChangePassword(username, true);

    emitAuthEvent("auth:otp:generated" as any, {
      username,
      expiryHours,
    });

    return { rawOTP, expiresAt: expiresAt.toISOString() };
  }

  /**
   * Changes password when forced (e.g. upon first login with OTP).
   */
  async changePasswordForced(
    username: string,
    newPassword: string
  ): Promise<{ success: boolean; message: string }> {
    if (!newPassword || newPassword.length < 8) {
      throw new MbkAuthError(
        ErrorCodes.INVALID_PASSWORD_LENGTH,
        400,
        "New password must be at least 8 characters long."
      );
    }

    const passwordHash = hashPassword(newPassword, username);
    await this.userRepo.updatePassword(username, passwordHash);
    await this.userRepo.setMustChangePassword(username, false);
    await this.challengeRepo.clearChallengesForUser(username);

    emitAuthEvent("auth:password:changed" as any, {
      username,
      method: "forced_change",
    });

    return { success: true, message: "Password updated successfully." };
  }
}

export const authResetService = new AuthResetService();
