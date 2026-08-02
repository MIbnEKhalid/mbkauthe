-- SQLite schema for mbkauthe.
--
-- This mirrors the auth-relevant subset of docs/schema/db.sql (Postgres).
-- Tables belonging to the wider MBKTech platform rather than mbkauthe
-- itself (todos, notifications, categories, etc.) are intentionally not
-- included here — add those separately in your own app schema if needed.
--
-- Notes on the Postgres -> SQLite translation:
--   * "integer GENERATED ... AS IDENTITY"   -> INTEGER PRIMARY KEY AUTOINCREMENT
--   * "boolean"                             -> INTEGER (0/1)
--   * "jsonb"/"json"                        -> TEXT (store JSON as text)
--   * "timestamp with time zone"            -> TEXT (CURRENT_TIMESTAMP format)
--   * "uuid DEFAULT gen_random_uuid()"      -> TEXT DEFAULT (uuid v4 expression)
--   * GIN indexes / COMMENT ON TABLE        -> omitted (no SQLite equivalent)

PRAGMA foreign_keys = ON;

-- Table: Users
CREATE TABLE IF NOT EXISTS "Users" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    "UserName" TEXT UNIQUE,
    "Password" TEXT DEFAULT '12345670',
    "Active" INTEGER DEFAULT 0,
    "Role" TEXT DEFAULT 'NormalUser',
    "HaveMailAccount" INTEGER DEFAULT 0,
    "AllowedApps" TEXT DEFAULT '["Portal", "mbkauthe"]',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_login TEXT,
    "PasswordEnc" TEXT,
    "FullName" TEXT,
    "UserId" TEXT UNIQUE CHECK ("UserId" IS NULL OR length("UserId") = 9),
    email TEXT DEFAULT 'support@mbktech.org',
    "Image" TEXT DEFAULT 'https://portal.mbktech.org/icon.svg',
    "Bio" TEXT DEFAULT 'I am ....',
    "SocialAccounts" TEXT DEFAULT '{}',
    "Positions" TEXT DEFAULT '{"Not_Permanent": "Member Is Not Permanent"}'
);
CREATE INDEX IF NOT EXISTS idx_users_active ON "Users" ("Active");
CREATE INDEX IF NOT EXISTS idx_users_email ON "Users" (email);
CREATE INDEX IF NOT EXISTS idx_users_last_login ON "Users" (last_login);
CREATE INDEX IF NOT EXISTS idx_users_role ON "Users" ("Role");
CREATE INDEX IF NOT EXISTS idx_users_username ON "Users" ("UserName");
CREATE INDEX IF NOT EXISTS idx_users_userid ON "Users" ("UserId");

-- Table: ApiTokens
CREATE TABLE IF NOT EXISTS "ApiTokens" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    "UserName" TEXT NOT NULL REFERENCES "Users"("UserName") ON DELETE CASCADE,
    "Name" TEXT NOT NULL CHECK (length(trim("Name")) > 0),
    "TokenHash" TEXT NOT NULL UNIQUE,
    "Prefix" TEXT NOT NULL,
    "Permissions" TEXT DEFAULT '{"scope": "read-only", "allowedApps": null}' NOT NULL,
    "LastUsed" TEXT,
    "CreatedAt" TEXT DEFAULT CURRENT_TIMESTAMP,
    "ExpiresAt" TEXT,
    CHECK ("ExpiresAt" IS NULL OR "ExpiresAt" > "CreatedAt")
);
CREATE INDEX IF NOT EXISTS idx_apitokens_expires ON "ApiTokens" ("ExpiresAt") WHERE "ExpiresAt" IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_apitokens_username_created ON "ApiTokens" ("UserName", "CreatedAt" DESC);

-- Table: ApiTokenProfiles
-- Predefined API token templates managed by MBKCore. MBKAuthe consumes these
-- (read-only) during CLI / device-flow token issuance.
CREATE TABLE IF NOT EXISTS "ApiTokenProfiles" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    "ProfileKey" TEXT,
    "Name" TEXT NOT NULL,
    "Description" TEXT,
    "AllowedApps" TEXT,
    "Scope" TEXT DEFAULT 'read-only' NOT NULL,
    "ExpiresInDays" INTEGER,
    "Active" INTEGER DEFAULT 1 NOT NULL,
    "CreatedAt" TEXT DEFAULT CURRENT_TIMESTAMP,
    "UpdatedAt" TEXT DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ApiTokenProfiles_Name_key" UNIQUE ("Name"),
    CONSTRAINT "ApiTokenProfiles_ProfileKey_key" UNIQUE ("ProfileKey"),
    CONSTRAINT chk_apitokenprofiles_scope CHECK (("Scope" IN ('read-only', 'write'))),
    CONSTRAINT chk_apitokenprofiles_expires CHECK (("ExpiresInDays" IS NULL) OR ("ExpiresInDays" > 0))
);
CREATE INDEX IF NOT EXISTS idx_apitokenprofiles_active ON "ApiTokenProfiles" ("Active");

-- Table: CliAuthSessions
-- One-time device-authorization sessions backing the browser-based CLI login
-- flow (RFC 8628-style). MBKAuthe owns this table.
CREATE TABLE IF NOT EXISTS "CliAuthSessions" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    "DeviceCodeHash" TEXT NOT NULL,
    "UserCodeHash" TEXT NOT NULL,
    "ClientName" TEXT NOT NULL,
    "ProfileId" INTEGER NOT NULL,
    "UserName" TEXT,
    "TokenId" INTEGER,
    "PendingToken" TEXT,
    "Status" TEXT DEFAULT 'pending' NOT NULL,
    "ExpiresAt" TEXT NOT NULL,
    "CreatedAt" TEXT DEFAULT CURRENT_TIMESTAMP,
    "ApprovedAt" TEXT,
    CONSTRAINT "CliAuthSessions_DeviceCodeHash_key" UNIQUE ("DeviceCodeHash"),
    CONSTRAINT "CliAuthSessions_UserCodeHash_key" UNIQUE ("UserCodeHash"),
    CONSTRAINT chk_cliauthsessions_status CHECK (("Status" IN ('pending', 'approved', 'completed', 'denied', 'expired')))
);
CREATE INDEX IF NOT EXISTS idx_cliauthsessions_expires ON "CliAuthSessions" ("ExpiresAt");
CREATE INDEX IF NOT EXISTS idx_cliauthsessions_status ON "CliAuthSessions" ("Status");

-- Table: PasswordResets
CREATE TABLE IF NOT EXISTS "PasswordResets" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    "UserName" TEXT NOT NULL REFERENCES "Users"("UserName") ON DELETE CASCADE,
    "resetToken" TEXT,
    "resetTokenExpires" TEXT,
    "resetAttempts" INTEGER DEFAULT 0,
    "lastResetAttempt" TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_password_resets_token ON "PasswordResets" ("resetToken");

-- Table: Sessions (mbkauthe's own app-session table — distinct from the
-- express-session store table below, which is just "session")
CREATE TABLE IF NOT EXISTS "Sessions" (
    id TEXT PRIMARY KEY DEFAULT (
        lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' ||
        substr(lower(hex(randomblob(2))), 2) || '-' ||
        substr('89ab', (abs(random()) % 4) + 1, 1) || substr(lower(hex(randomblob(2))), 2) || '-' ||
        lower(hex(randomblob(6)))
    ),
    "UserName" TEXT NOT NULL REFERENCES "Users"("UserName") ON DELETE CASCADE,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT,
    meta TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON "Sessions" (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_user_created ON "Sessions" ("UserName", created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_username_expires ON "Sessions" ("UserName", expires_at);

-- Table: TrustedDevices
CREATE TABLE IF NOT EXISTS "TrustedDevices" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    "UserName" TEXT NOT NULL REFERENCES "Users"("UserName") ON DELETE CASCADE,
    "DeviceToken" TEXT NOT NULL UNIQUE,
    "DeviceName" TEXT,
    "UserAgent" TEXT,
    "IpAddress" TEXT,
    "CreatedAt" TEXT DEFAULT CURRENT_TIMESTAMP,
    "ExpiresAt" TEXT NOT NULL,
    "LastUsed" TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_trusted_devices_expires ON "TrustedDevices" ("ExpiresAt");
CREATE INDEX IF NOT EXISTS idx_trusted_devices_username_expires ON "TrustedDevices" ("UserName", "ExpiresAt");
CREATE INDEX IF NOT EXISTS idx_trusted_devices_token_user_expires ON "TrustedDevices" ("DeviceToken", "UserName", "ExpiresAt");

-- Table: TwoFA
CREATE TABLE IF NOT EXISTS "TwoFA" (
    "UserName" TEXT NOT NULL PRIMARY KEY REFERENCES "Users"("UserName") ON DELETE CASCADE,
    "TwoFAStatus" INTEGER DEFAULT 0 NOT NULL,
    "TwoFASecret" TEXT
);
CREATE INDEX IF NOT EXISTS idx_twofa_username_status ON "TwoFA" ("UserName", "TwoFAStatus");

-- Table: session (express-session store; see lib/session/SqliteSessionStore.js)
CREATE TABLE IF NOT EXISTS "session" (
    sid TEXT PRIMARY KEY,
    sess TEXT NOT NULL,
    expire TEXT NOT NULL,
    username TEXT REFERENCES "Users"("UserName") ON DELETE CASCADE,
    last_activity TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_session_expire ON "session" (expire);

-- Table: user_github
CREATE TABLE IF NOT EXISTS user_github (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_name TEXT REFERENCES "Users"("UserName") ON DELETE CASCADE,
    github_id TEXT UNIQUE,
    github_username TEXT,
    access_token TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    installation_id INTEGER,
    installation_target_type TEXT
);
CREATE INDEX IF NOT EXISTS idx_user_github_user_name ON user_github (user_name);

-- Table: user_google
CREATE TABLE IF NOT EXISTS user_google (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_name TEXT REFERENCES "Users"("UserName"),
    google_id TEXT UNIQUE,
    google_email TEXT,
    access_token TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Seed user (hash-only). Default password is "12345678" for this sample account.
-- Hash was generated using mbkauthe's "hashPassword(password, username)" function.
INSERT INTO "Users" ("UserName", "PasswordEnc", "Role", "Active", "HaveMailAccount", "FullName")
VALUES ('support', 'b8b10c1c9006d8c30ab81c412463c65ff6dae3293d9bfbaf5fd8e275081d0947f000a828004e2fbd3a8f6ef5a35ae3eddd4c57b00ecab376b12e607a16a57459', 'SuperAdmin', 1, 0, 'Support User')
ON CONFLICT("UserName") DO NOTHING;
