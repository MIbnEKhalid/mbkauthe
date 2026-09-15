import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type GenerateRegistrationOptionsOpts,
  type GenerateAuthenticationOptionsOpts,
  type VerifyRegistrationResponseOpts,
  type VerifyAuthenticationResponseOpts,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON,
  type AuthenticatorTransport,
} from "@simplewebauthn/server";
import { AuthRepository, authRepository } from "../db/repositories/AuthRepository.js";
import { PasskeyRepository, passkeyRepository } from "../db/repositories/PasskeyRepository.js";
import { mbkautheVar } from "../config/index.js";
import { MbkAuthError } from "../core/errors/MbkAuthError.js";
import { ErrorCodes } from "../core/errors/catalog.js";
import { emitAuthEvent } from "../core/events/index.js";
import { AuthUser } from "../core/types/user.types.js";
import { createLogger } from "../utils/logger.js";
import { authorizationService } from "../core/permissions/AuthorizationService.js";

const debug = createLogger("mbkauthe:passkey-service");

export interface PasskeyServiceOptions {
  rpName?: string;
  rpID?: string;
  origin?: string | string[];
}

export class PasskeyService {
  constructor(
    private authRepo: AuthRepository = authRepository,
    private passkeysRepo: PasskeyRepository = passkeyRepository,
    private options: PasskeyServiceOptions = {}
  ) {}

  /**
   * Resolves the Relying Party ID (hostname).
   */
  getRpId(reqHostname?: string): string {
    if (this.options.rpID) return this.options.rpID;
    const configuredDomain = mbkautheVar.DOMAIN || mbkautheVar.domain || "localhost";
    const cleanDomain = configuredDomain.toLowerCase().replace(/:\d+$/, "").replace(/^\.+/, "");

    if (reqHostname) {
      const cleanHost = reqHostname.toLowerCase().replace(/:\d+$/, "").replace(/^\.+/, "");
      if (cleanHost === "localhost" || cleanHost === "127.0.0.1") {
        return cleanHost;
      }
      if (cleanHost === cleanDomain || cleanHost.endsWith(`.${cleanDomain}`)) {
        return cleanDomain;
      }
      if (mbkautheVar.IS_DEPLOYED === "f" || mbkautheVar.IS_DEPLOYED === false) {
        return cleanHost;
      }
    }
    return cleanDomain;
  }

  /**
   * Resolves the Relying Party Name.
   */
  getRpName(): string {
    return this.options.rpName || mbkautheVar.APP_NAME || "MBKTech";
  }

  /**
   * Resolves allowed origins for WebAuthn ceremony.
   */
  getExpectedOrigins(reqOrigin?: string, reqHostname?: string): string[] {
    if (this.options.origin) {
      return Array.isArray(this.options.origin) ? this.options.origin : [this.options.origin];
    }
    const rpId = this.getRpId(reqHostname);
    const origins = new Set<string>();

    origins.add(`http://${rpId}`);
    origins.add(`https://${rpId}`);

    if (rpId === "localhost" || rpId === "127.0.0.1") {
      origins.add("http://localhost");
      origins.add("https://localhost");
      origins.add("http://127.0.0.1");
      origins.add("https://127.0.0.1");
      [3000, 3001, 3002, 3003, 3004, 3005, 4000, 5000, 5001, 5173, 8000, 8080].forEach((port) => {
        origins.add(`http://localhost:${port}`);
        origins.add(`https://localhost:${port}`);
        origins.add(`http://127.0.0.1:${port}`);
        origins.add(`https://127.0.0.1:${port}`);
      });
    } else {
      origins.add(`https://${rpId}`);
      origins.add(`http://${rpId}`);
      origins.add(`https://auth.${rpId}`);
      origins.add(`https://portal.${rpId}`);
    }

    if (reqOrigin) {
      try {
        const parsed = new URL(reqOrigin);
        origins.add(reqOrigin);
        origins.add(`${parsed.protocol}//${parsed.host}`);
      } catch {}
    }

    return Array.from(origins);
  }

  /**
   * Generates WebAuthn registration options for a user.
   */
  async generateRegistrationOptions(username: string, userDisplayName?: string, reqHostname?: string): Promise<any> {
    debug("Generating registration options for username: %s (host: %s)", username, reqHostname);

    const existingPasskeys = await this.passkeysRepo.listByUsername(username);
    const excludeCredentials = existingPasskeys.map((pk) => {
      let transports: AuthenticatorTransport[] = [];
      try {
        if (pk.transports) {
          transports = typeof pk.transports === "string" ? JSON.parse(pk.transports) : pk.transports;
        }
      } catch {}
      return {
        id: pk.credential_id,
        transports,
      };
    });

    const opts: GenerateRegistrationOptionsOpts = {
      rpName: this.getRpName(),
      rpID: this.getRpId(reqHostname),
      userName: username,
      userDisplayName: userDisplayName || username,
      attestationType: "none",
      excludeCredentials,
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
    };

    const options = await generateRegistrationOptions(opts);
    return options;
  }

  /**
   * Verifies the WebAuthn registration response and registers the passkey.
   */
  async verifyRegistration(
    username: string,
    response: RegistrationResponseJSON,
    expectedChallenge: string,
    friendlyName?: string,
    reqOrigin?: string,
    reqHostname?: string
  ): Promise<{ verified: boolean; passkeyId: number }> {
    debug("Verifying registration for username: %s", username);

    const expectedOrigin = this.getExpectedOrigins(reqOrigin, reqHostname);
    const expectedRPID = this.getRpId(reqHostname);

    const verificationOpts: VerifyRegistrationResponseOpts = {
      response,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      requireUserVerification: false,
    };

    const verification = await verifyRegistrationResponse(verificationOpts);

    if (!verification.verified || !verification.registrationInfo) {
      throw new MbkAuthError(ErrorCodes.TWO_FA_INVALID_TOKEN, 400, "Passkey registration verification failed");
    }

    const { credential, credentialDeviceType, credentialBackedUp, aaguid } = verification.registrationInfo;

    const publicKeyBase64 = Buffer.from(credential.publicKey).toString("base64url");
    const nameToUse = (friendlyName && friendlyName.trim()) || "Passkey";

    const passkey = await this.passkeysRepo.createPasskey({
      username,
      credential_id: credential.id,
      public_key: publicKeyBase64,
      counter: credential.counter,
      device_type: credentialDeviceType,
      backed_up: credentialBackedUp,
      transports: credential.transports,
      name: nameToUse,
      aaguid: aaguid || undefined,
    });

    debug("Passkey registered successfully with ID: %s for user: %s", passkey.id, username);

    return {
      verified: true,
      passkeyId: passkey.id,
    };
  }

  /**
   * Generates WebAuthn authentication options.
   */
  async generateAuthenticationOptions(username?: string, reqHostname?: string): Promise<any> {
    debug("Generating authentication options (target user: %s, host: %s)", username || "any", reqHostname);

    let allowCredentials: { id: string; transports?: AuthenticatorTransport[] }[] | undefined;

    if (username) {
      const userPasskeys = await this.passkeysRepo.listByUsername(username);
      if (userPasskeys.length > 0) {
        allowCredentials = userPasskeys.map((pk) => {
          let transports: AuthenticatorTransport[] = [];
          try {
            if (pk.transports) {
              transports = typeof pk.transports === "string" ? JSON.parse(pk.transports) : pk.transports;
            }
          } catch {}
          return {
            id: pk.credential_id,
            transports,
          };
        });
      }
    }

    const opts: GenerateAuthenticationOptionsOpts = {
      rpID: this.getRpId(reqHostname),
      allowCredentials,
      userVerification: "preferred",
    };

    const options = await generateAuthenticationOptions(opts);
    return options;
  }

  /**
   * Verifies the WebAuthn authentication response and returns the authenticated user.
   */
  async verifyAuthentication(
    response: AuthenticationResponseJSON,
    expectedChallenge: string,
    reqOrigin?: string,
    options: { ip?: string; userAgent?: string; appKey?: string; reqHostname?: string } = {}
  ): Promise<{ verified: boolean; user: AuthUser; passkeyId: number }> {
    const { ip, userAgent, appKey, reqHostname } = options;
    const credentialId = response.id;
    debug("Verifying passkey authentication for credential ID: %s", credentialId);

    const passkeyRecord = await this.passkeysRepo.findByCredentialId(credentialId);
    if (!passkeyRecord) {
      emitAuthEvent("auth:login:failed", { username: "unknown", reason: "PASSKEY_NOT_FOUND", ip, userAgent, appKey });
      throw new MbkAuthError(ErrorCodes.USER_NOT_FOUND, 401, "Passkey not recognized");
    }

    const { user, public_key, counter, transports } = passkeyRecord;

    if (user.is_active === false) {
      emitAuthEvent("auth:login:failed", { username: user.username, reason: "ACCOUNT_INACTIVE", ip, userAgent, appKey });
      throw new MbkAuthError(ErrorCodes.ACCOUNT_INACTIVE, 403, "User account is inactive");
    }

    if (!authorizationService.canAccessApp(user, appKey)) {
      emitAuthEvent("auth:login:failed", { username: user.username, reason: "APP_NOT_AUTHORIZED", ip, userAgent, appKey });
      throw new MbkAuthError(ErrorCodes.APP_NOT_AUTHORIZED, 403, "User not authorized for this application");
    }

    const expectedOrigin = this.getExpectedOrigins(reqOrigin, reqHostname);
    const expectedRPID = this.getRpId(reqHostname);

    let parsedTransports: AuthenticatorTransport[] = [];
    try {
      if (transports) {
        parsedTransports = typeof transports === "string" ? JSON.parse(transports) : transports;
      }
    } catch {}

    const publicKeyUint8 = Uint8Array.from(Buffer.from(public_key, "base64url"));

    const verificationOpts: VerifyAuthenticationResponseOpts = {
      response,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      credential: {
        id: credentialId,
        publicKey: publicKeyUint8,
        counter: Number(counter || 0),
        transports: parsedTransports,
      },
      requireUserVerification: false,
    };

    const verification = await verifyAuthenticationResponse(verificationOpts);

    if (!verification.verified || !verification.authenticationInfo) {
      emitAuthEvent("auth:login:failed", { username: user.username, reason: "PASSKEY_VERIFICATION_FAILED", ip, userAgent, appKey });
      throw new MbkAuthError(ErrorCodes.TWO_FA_INVALID_TOKEN, 401, "Passkey authentication verification failed");
    }

    // Update replay attack counter and touch last used
    await this.passkeysRepo.updateCounterAndLastUsed(credentialId, verification.authenticationInfo.newCounter);

    emitAuthEvent("auth:login:success", {
      userId: user.user_id || user.username,
      username: user.username,
      ip,
      userAgent,
      appKey,
      authMethod: "passkey",
    });

    return {
      verified: true,
      user,
      passkeyId: passkeyRecord.id,
    };
  }

  /**
   * Lists all passkeys for a user.
   */
  async listUserPasskeys(username: string) {
    return this.passkeysRepo.listByUsername(username);
  }

  /**
   * Renames a user's passkey.
   */
  async renamePasskey(id: number | string, username: string, name: string) {
    if (!name || typeof name !== "string" || !name.trim()) {
      throw new MbkAuthError(ErrorCodes.MISSING_REQUIRED_FIELD, 400, "Passkey name is required");
    }
    return this.passkeysRepo.renamePasskey(id, username, name.trim());
  }

  /**
   * Deletes a user's passkey.
   */
  async deletePasskey(id: number | string, username: string) {
    return this.passkeysRepo.deleteByIdAndUsername(id, username);
  }
}

export const passkeyService = new PasskeyService();
