import { CliAuthSessionRepository, cliAuthSessionRepository } from "../db/repositories/CliAuthSessionRepository.js";
import { ApiTokenService, apiTokenService } from "./ApiTokenService.js";
import { TokenEngine } from "../core/tokens/TokenEngine.js";
import { emitAuthEvent } from "../core/events/index.js";
import { MbkAuthError } from "../core/errors/MbkAuthError.js";
import { ErrorCodes } from "../core/errors/catalog.js";
import { createLogger } from "../utils/logger.js";
import crypto from "node:crypto";

const debug = createLogger("mbkauthe:cli-auth-service");

export interface InitiateCliAuthParams {
  clientName?: string;
  profileKey?: string;
  expiresInSeconds?: number;
}

export interface CliAuthInitiateResult {
  device_code: string;
  user_code: string;
  verification_uri: string;
  expires_in: number;
  interval: number;
}

export interface PollCliAuthResult {
  status: "pending" | "approved" | "denied" | "expired" | "not_found";
  access_token?: string;
  token_type?: string;
  username?: string;
  error?: string;
}

function generateUserCode(): string {
  const chars = "BCDFGHJKLMNPQRSTVWXYZ23456789";
  let code = "";
  const bytes = crypto.randomBytes(8);
  for (let i = 0; i < 8; i++) {
    code += chars[bytes[i] % chars.length];
    if (i === 3) code += "-";
  }
  return code;
}

export class CliAuthService {
  constructor(
    private sessionRepo: CliAuthSessionRepository = cliAuthSessionRepository,
    private tokenService: ApiTokenService = apiTokenService
  ) {}

  /**
   * Initiates a new CLI device authorization flow
   */
  async initiate(params: InitiateCliAuthParams = {}): Promise<CliAuthInitiateResult> {
    const clientName = params.clientName || "CLI Client";
    const expiresIn = params.expiresInSeconds || 600; // 10 minutes default
    const expiresAt = new Date(Date.now() + expiresIn * 1000);

    let profileId: number | null = null;
    if (params.profileKey) {
      const profile = await this.sessionRepo.getActiveProfileByKey(params.profileKey);
      if (profile) profileId = Number(profile.id);
    }

    const rawDeviceCode = crypto.randomBytes(24).toString("hex");
    const rawUserCode = generateUserCode();

    const deviceCodeHash = TokenEngine.hashToken(rawDeviceCode)!;
    const userCodeHash = TokenEngine.hashToken(rawUserCode.replace(/[^A-Za-z0-9]/g, "").toUpperCase())!;

    await this.sessionRepo.create({
      device_code_hash: deviceCodeHash,
      user_code_hash: userCodeHash,
      client_name: clientName,
      profile_id: profileId,
      expires_at: expiresAt,
    });

    debug("Initiated CLI auth session for client '%s'", clientName);

    return {
      device_code: rawDeviceCode,
      user_code: rawUserCode,
      verification_uri: "/mbkauthe/cli/verify",
      expires_in: expiresIn,
      interval: 5,
    };
  }

  /**
   * Polls the status of a CLI authorization session using the device code
   */
  async poll(deviceCode: string): Promise<PollCliAuthResult> {
    if (!deviceCode) {
      return { status: "not_found", error: "Invalid device code" };
    }

    const deviceCodeHash = TokenEngine.hashToken(deviceCode)!;
    const session = await this.sessionRepo.findByDeviceCodeHash(deviceCodeHash);

    if (!session) {
      return { status: "not_found", error: "Session not found" };
    }

    const now = new Date();
    if (session.expires_at && new Date(session.expires_at) <= now && session.status === "pending") {
      await this.sessionRepo.markExpired(session.id);
      return { status: "expired", error: "Authorization expired" };
    }

    if (session.status === "denied") {
      return { status: "denied", error: "Authorization was denied by the user" };
    }

    if (session.status === "approved" && session.pending_token) {
      const token = session.pending_token;
      await this.sessionRepo.completeDelivery(session.id);
      return {
        status: "approved",
        access_token: token,
        token_type: "Bearer",
        username: session.username,
      };
    }

    if (session.status === "completed") {
      return { status: "expired", error: "Token already issued" };
    }

    return { status: "pending" };
  }

  /**
   * Approves a CLI authorization session for a verified user
   */
  async approve(rawUserCode: string, username: string): Promise<boolean> {
    if (!rawUserCode || !username) {
      throw new MbkAuthError(ErrorCodes.MISSING_REQUIRED_FIELD, 400, "User code and username required");
    }

    const normalizedCode = rawUserCode.replace(/[^A-Za-z0-9]/g, "").toUpperCase();
    const userCodeHash = TokenEngine.hashToken(normalizedCode)!;
    const session = await this.sessionRepo.findByUserCodeHash(userCodeHash);

    if (!session || session.status !== "pending") {
      throw new MbkAuthError(ErrorCodes.SESSION_NOT_FOUND, 404, "Authorization request not found or already processed");
    }

    const now = new Date();
    if (session.expires_at && new Date(session.expires_at) <= now) {
      await this.sessionRepo.markExpired(session.id);
      throw new MbkAuthError(ErrorCodes.SESSION_EXPIRED, 400, "Authorization request has expired");
    }

    // Determine scopes and expiry from profile if attached
    let scopes: string[] = ["cli:access"];
    let expiresInDays: number | null = 30;

    if (session.profile_id) {
      const profile = await this.sessionRepo.getActiveProfileById(session.profile_id);
      if (profile) {
        if (profile.permissions && profile.permissions.length > 0) {
          scopes = profile.permissions;
        }
        if (profile.expires_in_days) {
          expiresInDays = profile.expires_in_days;
        }
      }
    }

    const tokenName = `CLI: ${session.client_name || "Session"} (${normalizedCode.slice(0, 4)})`;
    const { token, tokenRecord } = await this.tokenService.createToken(username, {
      name: tokenName,
      scopes,
      expiresInDays,
    });

    const approved = await this.sessionRepo.markApproved(session.id, {
      username,
      token_id: tokenRecord.id,
      pending_token: token,
    });

    if (approved) {
      emitAuthEvent("auth:cli:approved", {
        deviceCode: session.device_code_hash,
        userCode: normalizedCode,
        userId: username,
      });
    }

    return approved;
  }

  /**
   * Denies a CLI authorization session
   */
  async deny(rawUserCode: string): Promise<boolean> {
    if (!rawUserCode) return false;
    const normalizedCode = rawUserCode.replace(/[^A-Za-z0-9]/g, "").toUpperCase();
    const userCodeHash = TokenEngine.hashToken(normalizedCode)!;
    const session = await this.sessionRepo.findByUserCodeHash(userCodeHash);

    if (!session || session.status !== "pending") return false;

    await this.sessionRepo.markDenied(session.id);
    emitAuthEvent("auth:cli:denied", {
      deviceCode: session.device_code_hash,
      userCode: normalizedCode,
    });
    return true;
  }
}

export const cliAuthService = new CliAuthService();
