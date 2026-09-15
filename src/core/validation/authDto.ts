import { MbkAuthError } from "../errors/MbkAuthError.js";
import { ErrorCodes } from "../errors/catalog.js";

export interface LoginDto {
  username: string;
  password: string;
  rememberMe?: boolean;
}

export interface VerifyTotpDto {
  token: string;
  rememberDevice?: boolean;
}

export interface CreateApiTokenDto {
  name: string;
  scopes: string[];
  expiresInDays?: number | null;
}

export interface CliDeviceCodeDto {
  deviceCode: string;
  userCode?: string;
}

/**
 * Validates and sanitizes username and password credentials
 */
export function validateLoginDto(input: any): LoginDto {
  if (!input || typeof input !== "object") {
    throw new MbkAuthError(ErrorCodes.MISSING_REQUIRED_FIELD, 400, "Missing credentials payload");
  }

  const username = typeof input.username === "string" ? input.username.trim() : "";
  const password = typeof input.password === "string" ? input.password : "";

  if (!username) {
    throw new MbkAuthError(ErrorCodes.MISSING_REQUIRED_FIELD, 400, "Username is required");
  }
  if (!password) {
    throw new MbkAuthError(ErrorCodes.MISSING_REQUIRED_FIELD, 400, "Password is required");
  }

  return {
    username,
    password,
    rememberMe: Boolean(input.rememberMe ?? input.remember_me),
  };
}

/**
 * Validates 2FA TOTP verification input
 */
export function validateTotpDto(input: any): VerifyTotpDto {
  if (!input || typeof input !== "object") {
    throw new MbkAuthError(ErrorCodes.MISSING_REQUIRED_FIELD, 400, "Missing 2FA payload");
  }

  const token = typeof input.token === "string" ? input.token.trim().replace(/\s+/g, "") : "";
  if (!token || !/^\d{6,8}$/.test(token)) {
    throw new MbkAuthError(ErrorCodes.INVALID_TOKEN_FORMAT, 400, "Invalid 2FA token format");
  }

  return {
    token,
    rememberDevice: Boolean(input.rememberDevice ?? input.remember_device),
  };
}

/**
 * Validates API Token creation parameters
 */
export function validateCreateApiTokenDto(input: any): CreateApiTokenDto {
  if (!input || typeof input !== "object") {
    throw new MbkAuthError(ErrorCodes.MISSING_REQUIRED_FIELD, 400, "Missing token creation payload");
  }

  const name = typeof input.name === "string" ? input.name.trim() : "";
  if (!name || name.length > 100) {
    throw new MbkAuthError(ErrorCodes.MISSING_REQUIRED_FIELD, 400, "Token name must be between 1 and 100 characters");
  }

  let scopes: string[] = [];
  if (Array.isArray(input.scopes)) {
    scopes = input.scopes.map((s: any) => String(s).trim()).filter(Boolean);
  } else if (typeof input.scopes === "string") {
    scopes = input.scopes.split(",").map((s: string) => s.trim()).filter(Boolean);
  }

  let expiresInDays: number | null = null;
  if (input.expiresInDays != null || input.expires_in_days != null) {
    const val = Number(input.expiresInDays ?? input.expires_in_days);
    if (!Number.isNaN(val) && val > 0) {
      expiresInDays = Math.floor(val);
    }
  }

  return {
    name,
    scopes,
    expiresInDays,
  };
}

/**
 * Validates CLI Device authentication payload
 */
export function validateCliDeviceCodeDto(input: any): CliDeviceCodeDto {
  if (!input || typeof input !== "object") {
    throw new MbkAuthError(ErrorCodes.MISSING_REQUIRED_FIELD, 400, "Missing CLI authorization payload");
  }

  const deviceCode = typeof input.deviceCode === "string" ? input.deviceCode.trim() : typeof input.device_code === "string" ? input.device_code.trim() : "";
  const userCode = typeof input.userCode === "string" ? input.userCode.trim() : typeof input.user_code === "string" ? input.user_code.trim() : undefined;

  if (!deviceCode) {
    throw new MbkAuthError(ErrorCodes.MISSING_REQUIRED_FIELD, 400, "device_code is required");
  }

  return {
    deviceCode,
    userCode,
  };
}
