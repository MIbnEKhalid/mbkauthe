/**
 * AES-256-GCM Token & Database Sensitive Field Encryption at Rest for MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import crypto from "node:crypto";
import type { OAuthTokenEncryptor } from "../ports.js";
import { mbkautheVar } from "../../config/index.js";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;

export function resolveDbEncryptionSecret(): string {
  if (process.env.DB_ENCRYPTION_KEY) return process.env.DB_ENCRYPTION_KEY;
  if (mbkautheVar?.DB_ENCRYPTION_KEY) return String(mbkautheVar.DB_ENCRYPTION_KEY);
  if (mbkautheVar?.db_encryption_key) return String(mbkautheVar.db_encryption_key);
  if (process.env.MAIN_SECRET_TOKEN) return process.env.MAIN_SECRET_TOKEN;
  if (mbkautheVar?.MAIN_SECRET_TOKEN) return String(mbkautheVar.MAIN_SECRET_TOKEN);
  if (mbkautheVar?.main_secret_token) return String(mbkautheVar.main_secret_token);

  try {
    if (process.env.mbkauthShared) {
      const parsed = JSON.parse(process.env.mbkauthShared);
      const secret =
        parsed.DB_ENCRYPTION_KEY ||
        parsed.db_encryption_key ||
        parsed.Main_SECRET_TOKEN ||
        parsed.MAIN_SECRET_TOKEN ||
        parsed.main_secret_token;
      if (secret) return String(secret);
    }
  } catch {}

  return "default-mbkauthe-oauth-secret-key";
}

export class AesGcmTokenEncryptor implements OAuthTokenEncryptor {
  private explicitKey?: Buffer;

  constructor(secretOrKey?: string) {
    if (secretOrKey) {
      this.explicitKey = crypto.createHash("sha256").update(secretOrKey).digest();
    }
  }

  private getKey(): Buffer {
    if (this.explicitKey) return this.explicitKey;
    const secret = resolveDbEncryptionSecret();
    return crypto.createHash("sha256").update(secret).digest();
  }

  /**
   * Encrypts plain text string using AES-256-GCM.
   * If already encrypted (starts with "enc:v1:"), returns as is (idempotent).
   */
  encrypt(plainText?: string | null): string | null {
    if (!plainText || typeof plainText !== "string") return null;
    if (plainText.startsWith("enc:v1:")) return plainText;

    try {
      const iv = crypto.randomBytes(IV_LENGTH);
      const cipher = crypto.createCipheriv(ALGORITHM, this.getKey(), iv);
      const encrypted = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
      const authTag = cipher.getAuthTag();

      // Format: enc:v1:<iv_hex>:<tag_hex>:<data_hex>
      return `enc:v1:${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted.toString("hex")}`;
    } catch (err) {
      console.error("[mbkauthe] Token encryption error:", err);
      return null;
    }
  }

  /**
   * Decrypts AES-256-GCM encrypted string.
   * Strict: requires ciphertext to start with enc:v1:. Returns null otherwise (no backward compatibility).
   */
  decrypt(cipherText?: string | null): string | null {
    if (!cipherText || typeof cipherText !== "string") return null;

    if (!cipherText.startsWith("enc:v1:")) {
      return null;
    }

    try {
      const parts = cipherText.split(":");
      if (parts.length !== 5) return null;

      const iv = Buffer.from(parts[2], "hex");
      const authTag = Buffer.from(parts[3], "hex");
      const encryptedData = Buffer.from(parts[4], "hex");

      const decipher = crypto.createDecipheriv(ALGORITHM, this.getKey(), iv);
      decipher.setAuthTag(authTag);
      const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

      return decrypted.toString("utf8");
    } catch (err) {
      console.error("[mbkauthe] Token decryption error:", err);
      return null;
    }
  }
}

export const defaultTokenEncryptor = new AesGcmTokenEncryptor();

export function encryptDbField(val?: string | null): string | null {
  return defaultTokenEncryptor.encrypt(val);
}

export function decryptDbField(val?: string | null): string | null {
  return defaultTokenEncryptor.decrypt(val);
}
