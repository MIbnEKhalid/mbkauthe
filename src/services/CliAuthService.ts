import crypto from "node:crypto";
import { CliAuthSessionRepository, cliAuthSessionRepository } from "../db/repositories/CliAuthSessionRepository.js";
import { ApiTokenRepository, apiTokenRepository } from "../db/repositories/ApiTokenRepository.js";
import { PermissionRepository, permissionRepository } from "../db/repositories/PermissionRepository.js";
import { ApiTokenService, apiTokenService } from "./ApiTokenService.js";
import { TokenEngine } from "../core/tokens/TokenEngine.js";
import { emitAuthEvent } from "../core/events/index.js";
import { MbkAuthError } from "../core/errors/MbkAuthError.js";
import { ErrorCodes } from "../core/errors/catalog.js";
import { intersectPermissions } from "../core/permissions/roleRegistry.js";
import { createLogger } from "../utils/logger.js";

const debug = createLogger("mbkauthe:cli-auth-service");

const USER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function generateUserCode(): string {
  let code = "";
  for (let i = 0; i < 8; i += 1) {
    code += USER_CODE_ALPHABET[crypto.randomInt(USER_CODE_ALPHABET.length)];
  }
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

export interface InitiateCliAuthParams {
  clientName?: string;
  profileKey?: string;
  profileId?: number | string;
  expiresInSeconds?: number;
  baseUrl?: string;
}

export interface CliAuthInitiateResult {
  success: boolean;
  device_code: string;
  user_code: string;
  verification_url: string;
  verification_uri: string;
  expires_in: number;
  interval: number;
  client_name: string;
  profile?: {
    id: number;
    key?: string;
    name: string;
    permissions: string[];
    expires_in_days?: number | null;
  } | null;
}

export interface PollCliAuthResult {
  success: boolean;
  status: "pending" | "approved" | "denied" | "expired" | "completed" | "not_found" | "invalid";
  token?: string;
  access_token?: string;
  token_type?: string;
  token_prefix?: string;
  username?: string;
  interval?: number;
  message?: string;
  error?: string;
}

export class CliAuthService {
  private tokenRepo: ApiTokenRepository;
  private permRepo: PermissionRepository;

  constructor(
    private sessionRepo: CliAuthSessionRepository = cliAuthSessionRepository,
    private tokenService: ApiTokenService = apiTokenService,
    tokenRepo?: ApiTokenRepository,
    permRepo?: PermissionRepository
  ) {
    this.tokenRepo = tokenRepo || (tokenService as any)?.tokenRepo || apiTokenRepository;
    this.permRepo = permRepo || permissionRepository;
  }

  private async findSessionByUserCode(rawUserCode: string) {
    if (!rawUserCode || typeof rawUserCode !== "string") return null;
    const clean = rawUserCode.trim().toUpperCase();
    const withHyphen = clean.includes("-") ? clean : (clean.length === 8 ? `${clean.slice(0, 4)}-${clean.slice(4)}` : clean);
    const withoutHyphen = clean.replace(/[^A-Za-z0-9]/g, "");

    let session = await this.sessionRepo.findByUserCodeHash(TokenEngine.hashToken(withHyphen)!);
    if (!session && withoutHyphen !== withHyphen) {
      session = await this.sessionRepo.findByUserCodeHash(TokenEngine.hashToken(withoutHyphen)!);
    }
    return { session, userCode: withHyphen };
  }

  /**
   * Initiates a new CLI device authorization flow
   */
  async initiate(params: InitiateCliAuthParams = {}): Promise<CliAuthInitiateResult> {
    const rawClientName = params.clientName;
    if (!rawClientName || typeof rawClientName !== "string" || !rawClientName.trim()) {
      throw new MbkAuthError(ErrorCodes.MISSING_REQUIRED_FIELD, 400, "client_name is required");
    }
    const clientName = rawClientName.trim();
    if (clientName.length > 255) {
      throw new MbkAuthError(ErrorCodes.MISSING_REQUIRED_FIELD, 400, "client_name must be 255 characters or less");
    }

    let profile: any = null;
    if (params.profileKey && typeof params.profileKey === "string" && params.profileKey.trim().length >= 6) {
      profile = await this.sessionRepo.getActiveProfileByKey(params.profileKey.trim());
    } else if (params.profileId !== undefined && params.profileId !== null) {
      const parsedProfileId = typeof params.profileId === "number" ? params.profileId : parseInt(String(params.profileId), 10);
      if (Number.isInteger(parsedProfileId) && parsedProfileId > 0) {
        profile = await this.sessionRepo.getActiveProfileById(parsedProfileId);
      }
    }

    if (!profile) {
      throw new MbkAuthError(
        ErrorCodes.MISSING_REQUIRED_FIELD,
        400,
        "A valid profile_key (or profile_id) for an active API token profile is required"
      );
    }

    const expiresIn = params.expiresInSeconds || 15 * 60; // 15 minutes default
    const expiresAt = new Date(Date.now() + expiresIn * 1000);

    const rawDeviceCode = TokenEngine.generateEntropy(24);
    const rawUserCode = generateUserCode();

    const deviceCodeHash = TokenEngine.hashToken(rawDeviceCode)!;
    const userCodeHash = TokenEngine.hashToken(rawUserCode)!;

    await this.sessionRepo.create({
      device_code_hash: deviceCodeHash,
      user_code_hash: userCodeHash,
      client_name: clientName,
      profile_id: profile.id,
      expires_at: expiresAt,
    });

    debug("Initiated CLI auth session for client '%s'", clientName);

    const verificationUrl = params.baseUrl
      ? `${params.baseUrl.replace(/\/+$/, "")}/mbkauthe/cli/device/${rawUserCode}`
      : `/mbkauthe/cli/device/${rawUserCode}`;

    return {
      success: true,
      verification_url: verificationUrl,
      verification_uri: verificationUrl,
      user_code: rawUserCode,
      device_code: rawDeviceCode,
      expires_in: expiresIn,
      interval: 5,
      client_name: clientName,
      profile: {
        id: profile.id,
        key: profile.profile_key,
        name: profile.name,
        permissions: profile.permissions ?? [],
        expires_in_days: profile.expires_in_days,
      },
    };
  }

  /**
   * Retrieves session info by user code for device approval UI
   */
  async getSessionByUserCode(rawUserCode: string): Promise<{
    session: any;
    profile: any;
    user_code: string;
    expires_in_seconds: number;
  }> {
    const found = await this.findSessionByUserCode(rawUserCode);
    const session = found?.session;
    const user_code = found?.userCode || rawUserCode;

    if (!session) {
      throw new MbkAuthError(ErrorCodes.RESOURCE_NOT_FOUND, 404, "This login request could not be found. The code may be invalid or already used.");
    }

    if (session.status === "pending" && new Date(session.expires_at) <= new Date()) {
      await this.sessionRepo.markExpired(session.id);
      session.status = "expired";
    }

    const profile = session.profile_id ? await this.sessionRepo.getProfileById(session.profile_id) : null;
    const expires_at = session.expires_at instanceof Date ? session.expires_at : new Date(session.expires_at);
    const expires_in_seconds = Math.max(0, Math.floor((expires_at.getTime() - Date.now()) / 1000));

    return {
      session,
      profile,
      user_code,
      expires_in_seconds,
    };
  }

  /**
   * Approves a CLI authorization session for a verified user
   */
  async approve(rawUserCode: string, username: string, options: { role?: string } = {}): Promise<boolean> {
    if (!rawUserCode || typeof rawUserCode !== "string") {
      throw new MbkAuthError(ErrorCodes.MISSING_REQUIRED_FIELD, 400, "user_code is required");
    }
    if (!username) {
      throw new MbkAuthError(ErrorCodes.MISSING_REQUIRED_FIELD, 400, "username is required");
    }

    const found = await this.findSessionByUserCode(rawUserCode);
    const session = found?.session;

    if (!session) {
      throw new MbkAuthError(ErrorCodes.RESOURCE_NOT_FOUND, 404, "Login request not found");
    }

    if (session.status !== "pending") {
      const err = new MbkAuthError(ErrorCodes.RESOURCE_NOT_FOUND, 409, `This request is already ${session.status}`);
      (err as any).status = session.status;
      throw err;
    }

    if (new Date(session.expires_at) <= new Date()) {
      await this.sessionRepo.markExpired(session.id);
      const err = new MbkAuthError(ErrorCodes.SESSION_EXPIRED, 410, "This login request has expired");
      (err as any).status = "expired";
      throw err;
    }

    const profile = session.profile_id ? await this.sessionRepo.getActiveProfileById(session.profile_id) : null;
    if (!profile) {
      await this.sessionRepo.markDenied(session.id);
      const err = new MbkAuthError(ErrorCodes.RESOURCE_NOT_FOUND, 400, "The requested API token profile is no longer available or is inactive. The login was cancelled.");
      (err as any).status = "denied";
      throw err;
    }

    const role = options.role;
    const MAX_API_TOKEN_LIMIT = 10;
    if (role && role !== "superadmin") {
      try {
        const count = await this.tokenRepo.countForUser(username);
        if (count >= MAX_API_TOKEN_LIMIT) {
          throw new MbkAuthError(ErrorCodes.INSUFFICIENT_PERMISSIONS, 403, `Token limit reached (max ${MAX_API_TOKEN_LIMIT}). Delete an existing token and try again.`);
        }
      } catch (err) {
        if (err instanceof MbkAuthError) throw err;
      }
    }

    const profilePermissions = Array.isArray(profile.permissions) ? profile.permissions : [];
    let tokenPermissions = profilePermissions;
    if (role && role !== "superadmin" && profilePermissions.length > 0) {
      try {
        const effective = await this.permRepo.computeEffectiveForUser(username);
        const intersected = intersectPermissions(effective.effective, profilePermissions);
        tokenPermissions = intersected.allows;
      } catch {
        // Fall back to profile permissions if permission repo is not available
      }
    }

    const tokenName = `${session.client_name} (CLI)`.slice(0, 255);
    const { token, tokenRecord } = await this.tokenService.createToken(username, {
      name: tokenName,
      scopes: tokenPermissions,
      expiresInDays: profile.expires_in_days ? parseInt(String(profile.expires_in_days), 10) : null,
    });

    const approved = await this.sessionRepo.markApproved(session.id, {
      username,
      token_id: tokenRecord.id,
      pending_token: token,
    });

    if (!approved) {
      await this.tokenRepo.deleteById(tokenRecord.id).catch(() => {});
      const err = new MbkAuthError(ErrorCodes.RESOURCE_NOT_FOUND, 409, "This request was already approved.");
      (err as any).status = "approved";
      throw err;
    }

    emitAuthEvent("auth:cli:approved", {
      deviceCode: session.device_code_hash,
      userCode: found?.userCode || rawUserCode,
      userId: username,
    });

    return true;
  }

  /**
   * Denies a CLI authorization session
   */
  async deny(rawUserCode: string): Promise<boolean> {
    if (!rawUserCode || typeof rawUserCode !== "string") return false;

    const found = await this.findSessionByUserCode(rawUserCode);
    const session = found?.session;

    if (!session || session.status !== "pending") return false;

    if (new Date(session.expires_at) <= new Date()) {
      await this.sessionRepo.markExpired(session.id);
      return false;
    }

    await this.sessionRepo.markDenied(session.id);
    emitAuthEvent("auth:cli:denied", {
      deviceCode: session.device_code_hash,
      userCode: found?.userCode || rawUserCode,
    });

    return true;
  }

  /**
   * Polls the status of a CLI authorization session using the device code
   */
  async poll(deviceCode: string): Promise<PollCliAuthResult> {
    if (!deviceCode || typeof deviceCode !== "string") {
      throw new MbkAuthError(ErrorCodes.MISSING_REQUIRED_FIELD, 400, "device_code is required");
    }

    const deviceCodeHash = TokenEngine.hashToken(deviceCode)!;
    const session = await this.sessionRepo.findByDeviceCodeHash(deviceCodeHash);

    if (!session) {
      throw new MbkAuthError(ErrorCodes.RESOURCE_NOT_FOUND, 404, "Invalid device code");
    }

    await this.sessionRepo.expireStale();

    if (session.status === "pending") {
      if (new Date(session.expires_at) <= new Date()) {
        await this.sessionRepo.markExpired(session.id);
        return { success: false, status: "expired", message: "Login request expired" };
      }
      return { success: false, status: "pending", interval: 5 };
    }

    if (session.status === "approved") {
      const delivered = await this.sessionRepo.completeDelivery(session.id);
      if (delivered && session.pending_token) {
        return {
          success: true,
          status: "approved",
          token: session.pending_token,
          access_token: session.pending_token,
          token_type: "Bearer",
          token_prefix: session.pending_token.substring(0, 8),
          username: session.username,
          message: "Login approved",
        };
      }
      return { success: false, status: "completed", message: "Token already delivered" };
    }

    if (session.status === "completed") {
      return { success: false, status: "completed", message: "Token already delivered" };
    }

    if (session.status === "denied") {
      return { success: false, status: "denied", message: "Login request denied" };
    }

    return { success: false, status: "expired", message: "Login request expired" };
  }
}

export const cliAuthService = new CliAuthService();

