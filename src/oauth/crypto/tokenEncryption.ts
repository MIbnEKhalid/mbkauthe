/**
 * AES-256-GCM Token Encryption at Rest for MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import crypto from "node:crypto";
import type { OAuthTokenEncryptor } from "../ports.js";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;

export class AesGcmTokenEncryptor implements OAuthTokenEncryptor {
  private key: Buffer;

  constructor(secretOrKey: string = "default-mbkauthe-oauth-secret-key") {
    // Derive 256-bit key
    this.key = crypto.createHash("sha256").update(secretOrKey).digest();
  }

  /**
   * Encrypts plain text string using AES-256-GCM.
   */
  encrypt(plainText?: string | null): string | null {
    if (!plainText || typeof plainText !== "string") return null;

    try {
      const iv = crypto.randomBytes(IV_LENGTH);
      const cipher = crypto.createCipheriv(ALGORITHM, this.key, iv);
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
   */
  decrypt(cipherText?: string | null): string | null {
    if (!cipherText || typeof cipherText !== "string") return null;

    try {
      if (!cipherText.startsWith("enc:v1:")) {
        // Not in current format (could be plain or legacy)
        return cipherText;
      }

      const parts = cipherText.split(":");
      if (parts.length !== 5) return null;

      const iv = Buffer.from(parts[2], "hex");
      const authTag = Buffer.from(parts[3], "hex");
      const encryptedData = Buffer.from(parts[4], "hex");

      const decipher = crypto.createDecipheriv(ALGORITHM, this.key, iv);
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
