import { describe, it, expect, beforeEach, afterEach, beforeAll } from "vitest";
import {
  encryptDbField,
  decryptDbField,
  AesGcmTokenEncryptor,
  defaultTokenEncryptor,
} from "../../src/oauth/crypto/tokenEncryption.js";
import { UserRepository } from "../../src/db/repositories/UserRepository.js";
import { OAuthAccountRepository } from "../../src/db/repositories/OAuthAccountRepository.js";
import { CliAuthSessionRepository } from "../../src/db/repositories/CliAuthSessionRepository.js";
import { SqlitePool } from "../../src/db/adapters/SqliteAdapter.js";
import { sqliteDialect } from "../../src/db/dialects/SqliteDialect.js";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe("Database Sensitive Data Encryption (AES-256-GCM)", () => {
  let pool;
  let schemaSql;
  let userRepo;
  let oauthRepo;
  let cliRepo;

  beforeAll(() => {
    const schemaPath = path.resolve(__dirname, "../../docs/schema/sqlite.sql");
    schemaSql = fs.readFileSync(schemaPath, "utf8");
  });

  beforeEach(async () => {
    pool = new SqlitePool(":memory:");
    pool.execScript(schemaSql);

    userRepo = new UserRepository({ db: pool, dialect: sqliteDialect });
    oauthRepo = new OAuthAccountRepository({ db: pool, dialect: sqliteDialect });
    cliRepo = new CliAuthSessionRepository({ db: pool, dialect: sqliteDialect });
  });

  afterEach(async () => {
    if (pool) await pool.end();
  });

  describe("Core Field-Level Encryption", () => {
    it("encrypts and decrypts strings correctly with enc:v1: prefix", () => {
      const plaintext = "JBSWY3DPEHPK3PXP"; // Typical TOTP base32 secret
      const encrypted = encryptDbField(plaintext);

      expect(encrypted).toBeDefined();
      expect(encrypted).not.toBe(plaintext);
      expect(encrypted?.startsWith("enc:v1:")).toBe(true);

      const decrypted = decryptDbField(encrypted);
      expect(decrypted).toBe(plaintext);
    });

    it("is idempotent: encrypting an already encrypted string does not double encrypt", () => {
      const plaintext = "my-secret-key-xyz";
      const enc1 = encryptDbField(plaintext);
      const enc2 = encryptDbField(enc1);

      expect(enc1).toBe(enc2);
      expect(decryptDbField(enc2)).toBe(plaintext);
    });

    it("strictly rejects unencrypted legacy values and returns null (no backward compatibility)", () => {
      const unencryptedLegacy = "LEGACY_PLAINTEXT_SECRET";
      expect(decryptDbField(unencryptedLegacy)).toBeNull();
    });

    it("handles null, undefined, and empty values gracefully", () => {
      expect(encryptDbField(null)).toBeNull();
      expect(encryptDbField(undefined)).toBeNull();
      expect(decryptDbField(null)).toBeNull();
      expect(decryptDbField(undefined)).toBeNull();
    });

    it("supports custom encryption keys and isolates distinct keys", () => {
      const encA = new AesGcmTokenEncryptor("key-alpha");
      const encB = new AesGcmTokenEncryptor("key-beta");

      const ciphertextA = encA.encrypt("shared-secret");
      expect(encA.decrypt(ciphertextA)).toBe("shared-secret");
      // Key B cannot decrypt Key A ciphertext
      expect(encB.decrypt(ciphertextA)).toBeNull();
    });
  });

  describe("2FA Secret Encryption at Rest (mbkcore_two_factor)", () => {
    it("encrypts 2FA secret in the database and decrypts transparently on read", async () => {
      // Seed user
      await pool.query(`INSERT INTO mbkcore_users (username) VALUES ('alice')`);

      const totpSecret = "KVKFKRCPNZQUYMLXOVYDSQKJKZDTSRLD";
      await userRepo.saveTwoFASecret("alice", totpSecret, true);

      // 1. Verify in raw database that the column is encrypted
      const rawRes = await pool.query(`SELECT two_fa_secret, is_enabled FROM mbkcore_two_factor WHERE username = 'alice'`);
      expect(rawRes.rows.length).toBe(1);
      const rawDbSecret = rawRes.rows[0].two_fa_secret;
      expect(rawDbSecret.startsWith("enc:v1:")).toBe(true);
      expect(rawDbSecret).not.toBe(totpSecret);

      // 2. Verify repository transparently decrypts the secret
      const fetched = await userRepo.getTwoFASecret("alice");
      expect(fetched).toBeDefined();
      expect(fetched?.two_fa_secret).toBe(totpSecret);
      expect(fetched?.is_enabled).toBe(true);
    });

    it("strictly returns null for unencrypted legacy 2FA secrets (no backward compatibility)", async () => {
      await pool.query(`INSERT INTO mbkcore_users (username) VALUES ('bob')`);
      const legacySecret = "UNENCRYPTED_LEGACY_SECRET";
      await pool.query(`INSERT INTO mbkcore_two_factor (username, is_enabled, two_fa_secret) VALUES ('bob', 1, '${legacySecret}')`);

      const fetched = await userRepo.getTwoFASecret("bob");
      expect(fetched?.two_fa_secret).toBeNull();
    });
  });

  describe("OAuth Token Encryption at Rest (mbkcore_oauth_accounts)", () => {
    it("encrypts access, refresh, and id tokens in the database", async () => {
      await pool.query(`INSERT INTO mbkcore_users (username) VALUES ('carol')`);

      const rawAccessToken = "ya29.a0AfH6SMD_mock_google_access_token";
      const rawRefreshToken = "1//04_mock_google_refresh_token";
      const rawIdToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.mock_id_token";

      const created = await oauthRepo.create({
        userId: "carol",
        providerId: "google",
        providerUserId: "google_123456",
        profile: { email: "carol@example.com" },
        encryptedAccessToken: rawAccessToken,
        encryptedRefreshToken: rawRefreshToken,
        encryptedIdToken: rawIdToken,
      });

      // 1. Verify in raw database that tokens are encrypted
      const rawRes = await pool.query(
        `SELECT access_token, refresh_token, id_token FROM mbkcore_oauth_accounts WHERE user_id = 'carol'`
      );
      expect(rawRes.rows.length).toBe(1);
      const row = rawRes.rows[0];

      expect(row.access_token.startsWith("enc:v1:")).toBe(true);
      expect(row.refresh_token.startsWith("enc:v1:")).toBe(true);
      expect(row.id_token.startsWith("enc:v1:")).toBe(true);

      expect(row.access_token).not.toBe(rawAccessToken);
      expect(row.refresh_token).not.toBe(rawRefreshToken);
      expect(row.id_token).not.toBe(rawIdToken);

      // 2. Verify getDecryptedTokens decrypts them back
      const decrypted = oauthRepo.getDecryptedTokens(created);
      expect(decrypted.accessToken).toBe(rawAccessToken);
      expect(decrypted.refreshToken).toBe(rawRefreshToken);
      expect(decrypted.idToken).toBe(rawIdToken);
    });

    it("encrypts tokens on update", async () => {
      await pool.query(`INSERT INTO mbkcore_users (username) VALUES ('dave')`);

      const created = await oauthRepo.create({
        userId: "dave",
        providerId: "github",
        providerUserId: "gh_789",
        encryptedAccessToken: "initial_token",
      });

      const updated = await oauthRepo.update(created.id, {
        encryptedAccessToken: "gho_new_rotated_token_999",
      });

      const rawRes = await pool.query(`SELECT access_token FROM mbkcore_oauth_accounts WHERE id = ?`, [created.id]);
      expect(rawRes.rows[0].access_token.startsWith("enc:v1:")).toBe(true);

      const decrypted = oauthRepo.getDecryptedTokens(updated);
      expect(decrypted.accessToken).toBe("gho_new_rotated_token_999");
    });
  });

  describe("CLI Pending Token Encryption (mbkcore_cli_auth_sessions)", () => {
    it("encrypts pending token on approval and decrypts upon retrieval", async () => {
      await pool.query(`INSERT INTO mbkcore_users (username) VALUES ('eve')`);

      const session = await cliRepo.create({
        device_code_hash: "hash_dev_123",
        user_code_hash: "hash_usr_456",
        client_name: "mbkcli-mac",
        profile_id: 1,
        expires_at: new Date(Date.now() + 600000),
      });

      const rawPendingToken = "mbk_tok_cli_live_credential_999";
      await cliRepo.markApproved(session.id, {
        username: "eve",
        token_id: 1,
        pending_token: rawPendingToken,
      });

      // 1. Verify in raw database that pending_token is encrypted at rest
      const rawRes = await pool.query(`SELECT pending_token FROM mbkcore_cli_auth_sessions WHERE id = ?`, [session.id]);
      expect(rawRes.rows[0].pending_token.startsWith("enc:v1:")).toBe(true);
      expect(rawRes.rows[0].pending_token).not.toBe(rawPendingToken);

      // 2. Verify repository decrypts it for delivery
      const approvedSession = await cliRepo.findByDeviceCodeHash("hash_dev_123");
      expect(approvedSession?.pending_token).toBe(rawPendingToken);
    });
  });
});
