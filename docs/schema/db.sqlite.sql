-- SQLite schema for mbkauthe (standard lowercase snake_case).
--
-- This mirrors the auth-relevant subset of docs/schema/db.sql (Postgres).
--
-- Notes on the Postgres -> SQLite translation:
--   * "integer GENERATED ... AS IDENTITY"   -> INTEGER PRIMARY KEY AUTOINCREMENT
--   * "boolean"                             -> INTEGER (0/1)
--   * "jsonb"/"json"                        -> TEXT (store JSON as text)
--   * "timestamp with time zone"            -> TEXT (CURRENT_TIMESTAMP format)
--   * "uuid DEFAULT gen_random_uuid()"      -> TEXT DEFAULT (uuid v4 expression)
--   * GIN indexes / COMMENT ON TABLE        -> omitted (no SQLite equivalent)

PRAGMA foreign_keys = ON;

-- Table: mbkcore_users
CREATE TABLE IF NOT EXISTS mbkcore_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE,
    password TEXT DEFAULT '12345670',
    is_active INTEGER DEFAULT 0,
    role TEXT DEFAULT 'normaluser',
    have_mail_account INTEGER DEFAULT 0,
    allowed_apps TEXT DEFAULT '["Portal", "mbkauthe"]',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_login TEXT,
    password_hash TEXT,
    full_name TEXT,
    user_id TEXT UNIQUE CHECK (user_id IS NULL OR length(user_id) = 9),
    email TEXT DEFAULT 'support@mbktech.org',
    image TEXT DEFAULT 'https://portal.mbktech.org/icon.svg',
    bio TEXT DEFAULT 'I am ....',
    social_accounts TEXT DEFAULT '{}',
    positions TEXT DEFAULT '{"Not_Permanent": "Member Is Not Permanent"}'
);
CREATE INDEX IF NOT EXISTS idx_mbkcore_users_is_active ON mbkcore_users (is_active);
CREATE INDEX IF NOT EXISTS idx_mbkcore_users_email ON mbkcore_users (email);
CREATE INDEX IF NOT EXISTS idx_mbkcore_users_last_login ON mbkcore_users (last_login);
CREATE INDEX IF NOT EXISTS idx_mbkcore_users_role ON mbkcore_users (role);
CREATE INDEX IF NOT EXISTS idx_mbkcore_users_username ON mbkcore_users (username);
CREATE INDEX IF NOT EXISTS idx_mbkcore_users_user_id ON mbkcore_users (user_id);

-- Table: mbkcore_api_tokens
CREATE TABLE IF NOT EXISTS mbkcore_api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL REFERENCES mbkcore_users(username) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    token_hash TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,
    permissions TEXT DEFAULT '{"scope": "read-only", "allowed_apps": null}' NOT NULL,
    last_used TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT,
    CHECK (expires_at IS NULL OR expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS idx_mbkcore_api_tokens_expires ON mbkcore_api_tokens (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mbkcore_api_tokens_username_created ON mbkcore_api_tokens (username, created_at DESC);

-- Table: mbkcore_api_token_profiles
CREATE TABLE IF NOT EXISTS mbkcore_api_token_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_key TEXT,
    name TEXT NOT NULL,
    description TEXT,
    allowed_apps TEXT,
    scope TEXT DEFAULT 'read-only' NOT NULL,
    expires_in_days INTEGER,
    is_active INTEGER DEFAULT 1 NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT mbkcore_api_token_profiles_name_key UNIQUE (name),
    CONSTRAINT mbkcore_api_token_profiles_profile_key_key UNIQUE (profile_key),
    CONSTRAINT chk_mbkcore_api_token_profiles_scope CHECK (scope IN ('read-only', 'write')),
    CONSTRAINT chk_mbkcore_api_token_profiles_expires CHECK (expires_in_days IS NULL OR expires_in_days > 0)
);
CREATE INDEX IF NOT EXISTS idx_mbkcore_api_token_profiles_is_active ON mbkcore_api_token_profiles (is_active);

-- Table: mbkcore_cli_auth_sessions
CREATE TABLE IF NOT EXISTS mbkcore_cli_auth_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_code_hash TEXT NOT NULL,
    user_code_hash TEXT NOT NULL,
    client_name TEXT NOT NULL,
    profile_id INTEGER NOT NULL,
    username VARCHAR(50),
    token_id INTEGER,
    pending_token TEXT,
    status TEXT DEFAULT 'pending' NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    approved_at TEXT,
    CONSTRAINT mbkcore_cli_auth_sessions_device_code_hash_key UNIQUE (device_code_hash),
    CONSTRAINT mbkcore_cli_auth_sessions_user_code_hash_key UNIQUE (user_code_hash),
    CONSTRAINT chk_mbkcore_cli_auth_sessions_status CHECK (status IN ('pending', 'approved', 'completed', 'denied', 'expired'))
);
CREATE INDEX IF NOT EXISTS idx_mbkcore_cli_auth_sessions_expires ON mbkcore_cli_auth_sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_mbkcore_cli_auth_sessions_status ON mbkcore_cli_auth_sessions (status);

-- Table: mbkcore_password_resets
CREATE TABLE IF NOT EXISTS mbkcore_password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL REFERENCES mbkcore_users(username) ON DELETE CASCADE,
    reset_token TEXT,
    reset_token_expires TEXT,
    reset_attempts INTEGER DEFAULT 0,
    last_reset_attempt TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_mbkcore_password_resets_token ON mbkcore_password_resets (reset_token);

-- Table: mbkcore_sessions (mbkauthe's app session table)
CREATE TABLE IF NOT EXISTS mbkcore_sessions (
    id TEXT PRIMARY KEY DEFAULT (
        lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' ||
        substr(lower(hex(randomblob(2))), 2) || '-' ||
        substr('89ab', (abs(random()) % 4) + 1, 1) || substr(lower(hex(randomblob(2))), 2) || '-' ||
        lower(hex(randomblob(6)))
    ),
    username VARCHAR(50) NOT NULL REFERENCES mbkcore_users(username) ON DELETE CASCADE,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT,
    meta TEXT
);
CREATE INDEX IF NOT EXISTS idx_mbkcore_sessions_expires ON mbkcore_sessions (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mbkcore_sessions_user_created ON mbkcore_sessions (username, created_at);
CREATE INDEX IF NOT EXISTS idx_mbkcore_sessions_username_expires ON mbkcore_sessions (username, expires_at);

-- Table: mbkcore_trusted_devices
CREATE TABLE IF NOT EXISTS mbkcore_trusted_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL REFERENCES mbkcore_users(username) ON DELETE CASCADE,
    device_token TEXT NOT NULL UNIQUE,
    device_name TEXT,
    user_agent TEXT,
    ip_address TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    last_used TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_mbkcore_trusted_devices_expires ON mbkcore_trusted_devices (expires_at);
CREATE INDEX IF NOT EXISTS idx_mbkcore_trusted_devices_username_expires ON mbkcore_trusted_devices (username, expires_at);
CREATE INDEX IF NOT EXISTS idx_mbkcore_trusted_devices_token_user_expires ON mbkcore_trusted_devices (device_token, username, expires_at);

-- Table: mbkcore_two_factor
CREATE TABLE IF NOT EXISTS mbkcore_two_factor (
    username VARCHAR(50) NOT NULL PRIMARY KEY REFERENCES mbkcore_users(username) ON DELETE CASCADE,
    is_enabled INTEGER DEFAULT 0 NOT NULL,
    two_fa_secret TEXT
);
CREATE INDEX IF NOT EXISTS idx_mbkcore_two_factor_username_status ON mbkcore_two_factor (username, is_enabled);

-- Table: mbkcore_session (express-session store)
CREATE TABLE IF NOT EXISTS mbkcore_session (
    sid TEXT PRIMARY KEY,
    sess TEXT NOT NULL,
    expire TEXT NOT NULL,
    username VARCHAR(50) REFERENCES mbkcore_users(username) ON DELETE CASCADE,
    last_activity TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_mbkcore_session_expire ON mbkcore_session (expire);

-- Table: mbkcore_user_github
CREATE TABLE IF NOT EXISTS mbkcore_user_github (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) REFERENCES mbkcore_users(username) ON DELETE CASCADE,
    github_id TEXT UNIQUE,
    github_username VARCHAR(255),
    access_token TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    installation_id INTEGER,
    installation_target_type TEXT
);
CREATE INDEX IF NOT EXISTS idx_mbkcore_user_github_username ON mbkcore_user_github (username);

-- Table: mbkcore_user_google
CREATE TABLE IF NOT EXISTS mbkcore_user_google (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) REFERENCES mbkcore_users(username),
    google_id TEXT UNIQUE,
    google_email TEXT,
    access_token TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Seed user (hash-only)
INSERT INTO mbkcore_users (username, password_hash, role, is_active, have_mail_account, full_name)
VALUES ('support', 'b8b10c1c9006d8c30ab81c412463c65ff6dae3293d9bfbaf5fd8e275081d0947f000a828004e2fbd3a8f6ef5a35ae3eddd4c57b00ecab376b12e607a16a57459', 'superadmin', 1, 0, 'Support User')
ON CONFLICT(username) DO NOTHING;
