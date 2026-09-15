import { describe, it, expect } from "vitest";
import { AesGcmTokenEncryptor } from "../../../src/oauth/crypto/tokenEncryption.js";

describe("AES-256-GCM Token Encryption", () => {
  const encryptor = new AesGcmTokenEncryptor("my-test-secret-key-12345");

  it("encrypts and decrypts sensitive plain text tokens", () => {
    const rawToken = "gho_16C7e42F292c6912E7710c838347Ae178B4a";
    const encrypted = encryptor.encrypt(rawToken);

    expect(encrypted).toBeDefined();
    expect(encrypted).not.toBe(rawToken);
    expect(encrypted?.startsWith("enc:v1:")).toBe(true);

    const decrypted = encryptor.decrypt(encrypted);
    expect(decrypted).toBe(rawToken);
  });

  it("produces different ciphertexts for same input (different IVs)", () => {
    const rawToken = "sample-access-token";
    const enc1 = encryptor.encrypt(rawToken);
    const enc2 = encryptor.encrypt(rawToken);

    expect(enc1).not.toBe(enc2);
    expect(encryptor.decrypt(enc1)).toBe(rawToken);
    expect(encryptor.decrypt(enc2)).toBe(rawToken);
  });

  it("handles null and undefined gracefully", () => {
    expect(encryptor.encrypt(null)).toBeNull();
    expect(encryptor.encrypt(undefined)).toBeNull();
    expect(encryptor.decrypt(null)).toBeNull();
    expect(encryptor.decrypt(undefined)).toBeNull();
  });

  it("fails to decrypt tampered ciphertexts", () => {
    const rawToken = "secret-jwt-token";
    const encrypted = encryptor.encrypt(rawToken);
    const tampered = encrypted?.slice(0, -4) + "ffff";

    const decrypted = encryptor.decrypt(tampered);
    expect(decrypted).toBeNull();
  });
});
