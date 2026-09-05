-- Migration: 001_to_lowercase.sql
-- Migrates MBKAuthe tables and columns from PascalCase / quoted identifiers to lowercase snake_case

BEGIN;

-- 1. Table: users (from "Users")
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'Users') THEN
    ALTER TABLE "Users" RENAME TO users;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'UserName') THEN
    ALTER TABLE users RENAME COLUMN "UserName" TO username;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'PasswordEnc') THEN
    ALTER TABLE users RENAME COLUMN "PasswordEnc" TO password_hash;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'Password') THEN
    ALTER TABLE users RENAME COLUMN "Password" TO password;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'Active') THEN
    ALTER TABLE users RENAME COLUMN "Active" TO is_active;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'Role') THEN
    ALTER TABLE users RENAME COLUMN "Role" TO role;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'HaveMailAccount') THEN
    ALTER TABLE users RENAME COLUMN "HaveMailAccount" TO have_mail_account;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'AllowedApps') THEN
    ALTER TABLE users RENAME COLUMN "AllowedApps" TO allowed_apps;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'FullName') THEN
    ALTER TABLE users RENAME COLUMN "FullName" TO full_name;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'UserId') THEN
    ALTER TABLE users RENAME COLUMN "UserId" TO user_id;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'Image') THEN
    ALTER TABLE users RENAME COLUMN "Image" TO image;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'Bio') THEN
    ALTER TABLE users RENAME COLUMN "Bio" TO bio;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'SocialAccounts') THEN
    ALTER TABLE users RENAME COLUMN "SocialAccounts" TO social_accounts;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'Positions') THEN
    ALTER TABLE users RENAME COLUMN "Positions" TO positions;
  END IF;
END $$;

-- 2. Table: api_tokens (from "ApiTokens")
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'ApiTokens') THEN
    ALTER TABLE "ApiTokens" RENAME TO api_tokens;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_tokens' AND column_name = 'UserName') THEN
    ALTER TABLE api_tokens RENAME COLUMN "UserName" TO username;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_tokens' AND column_name = 'Name') THEN
    ALTER TABLE api_tokens RENAME COLUMN "Name" TO name;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_tokens' AND column_name = 'TokenHash') THEN
    ALTER TABLE api_tokens RENAME COLUMN "TokenHash" TO token_hash;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_tokens' AND column_name = 'Prefix') THEN
    ALTER TABLE api_tokens RENAME COLUMN "Prefix" TO prefix;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_tokens' AND column_name = 'Permissions') THEN
    ALTER TABLE api_tokens RENAME COLUMN "Permissions" TO permissions;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_tokens' AND column_name = 'LastUsed') THEN
    ALTER TABLE api_tokens RENAME COLUMN "LastUsed" TO last_used;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_tokens' AND column_name = 'CreatedAt') THEN
    ALTER TABLE api_tokens RENAME COLUMN "CreatedAt" TO created_at;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_tokens' AND column_name = 'ExpiresAt') THEN
    ALTER TABLE api_tokens RENAME COLUMN "ExpiresAt" TO expires_at;
  END IF;
END $$;

-- 3. Table: api_token_profiles (from "ApiTokenProfiles")
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'ApiTokenProfiles') THEN
    ALTER TABLE "ApiTokenProfiles" RENAME TO api_token_profiles;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_token_profiles' AND column_name = 'ProfileKey') THEN
    ALTER TABLE api_token_profiles RENAME COLUMN "ProfileKey" TO profile_key;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_token_profiles' AND column_name = 'Name') THEN
    ALTER TABLE api_token_profiles RENAME COLUMN "Name" TO name;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_token_profiles' AND column_name = 'Description') THEN
    ALTER TABLE api_token_profiles RENAME COLUMN "Description" TO description;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_token_profiles' AND column_name = 'AllowedApps') THEN
    ALTER TABLE api_token_profiles RENAME COLUMN "AllowedApps" TO allowed_apps;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_token_profiles' AND column_name = 'Scope') THEN
    ALTER TABLE api_token_profiles RENAME COLUMN "Scope" TO scope;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_token_profiles' AND column_name = 'ExpiresInDays') THEN
    ALTER TABLE api_token_profiles RENAME COLUMN "ExpiresInDays" TO expires_in_days;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_token_profiles' AND column_name = 'Active') THEN
    ALTER TABLE api_token_profiles RENAME COLUMN "Active" TO is_active;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_token_profiles' AND column_name = 'CreatedAt') THEN
    ALTER TABLE api_token_profiles RENAME COLUMN "CreatedAt" TO created_at;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_token_profiles' AND column_name = 'UpdatedAt') THEN
    ALTER TABLE api_token_profiles RENAME COLUMN "UpdatedAt" TO updated_at;
  END IF;
END $$;

-- 4. Table: cli_auth_sessions (from "CliAuthSessions")
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'CliAuthSessions') THEN
    ALTER TABLE "CliAuthSessions" RENAME TO cli_auth_sessions;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cli_auth_sessions' AND column_name = 'DeviceCodeHash') THEN
    ALTER TABLE cli_auth_sessions RENAME COLUMN "DeviceCodeHash" TO device_code_hash;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cli_auth_sessions' AND column_name = 'UserCodeHash') THEN
    ALTER TABLE cli_auth_sessions RENAME COLUMN "UserCodeHash" TO user_code_hash;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cli_auth_sessions' AND column_name = 'ClientName') THEN
    ALTER TABLE cli_auth_sessions RENAME COLUMN "ClientName" TO client_name;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cli_auth_sessions' AND column_name = 'ProfileId') THEN
    ALTER TABLE cli_auth_sessions RENAME COLUMN "ProfileId" TO profile_id;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cli_auth_sessions' AND column_name = 'UserName') THEN
    ALTER TABLE cli_auth_sessions RENAME COLUMN "UserName" TO username;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cli_auth_sessions' AND column_name = 'TokenId') THEN
    ALTER TABLE cli_auth_sessions RENAME COLUMN "TokenId" TO token_id;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cli_auth_sessions' AND column_name = 'PendingToken') THEN
    ALTER TABLE cli_auth_sessions RENAME COLUMN "PendingToken" TO pending_token;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cli_auth_sessions' AND column_name = 'Status') THEN
    ALTER TABLE cli_auth_sessions RENAME COLUMN "Status" TO status;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cli_auth_sessions' AND column_name = 'ExpiresAt') THEN
    ALTER TABLE cli_auth_sessions RENAME COLUMN "ExpiresAt" TO expires_at;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cli_auth_sessions' AND column_name = 'CreatedAt') THEN
    ALTER TABLE cli_auth_sessions RENAME COLUMN "CreatedAt" TO created_at;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cli_auth_sessions' AND column_name = 'ApprovedAt') THEN
    ALTER TABLE cli_auth_sessions RENAME COLUMN "ApprovedAt" TO approved_at;
  END IF;
END $$;

-- 5. Table: password_resets (from "PasswordResets")
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'PasswordResets') THEN
    ALTER TABLE "PasswordResets" RENAME TO password_resets;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'password_resets' AND column_name = 'UserName') THEN
    ALTER TABLE password_resets RENAME COLUMN "UserName" TO username;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'password_resets' AND column_name = 'resetToken') THEN
    ALTER TABLE password_resets RENAME COLUMN "resetToken" TO reset_token;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'password_resets' AND column_name = 'resetTokenExpires') THEN
    ALTER TABLE password_resets RENAME COLUMN "resetTokenExpires" TO reset_token_expires;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'password_resets' AND column_name = 'resetAttempts') THEN
    ALTER TABLE password_resets RENAME COLUMN "resetAttempts" TO reset_attempts;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'password_resets' AND column_name = 'lastResetAttempt') THEN
    ALTER TABLE password_resets RENAME COLUMN "lastResetAttempt" TO last_reset_attempt;
  END IF;
END $$;

-- 6. Table: sessions (from "Sessions")
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'Sessions') THEN
    ALTER TABLE "Sessions" RENAME TO sessions;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'sessions' AND column_name = 'UserName') THEN
    ALTER TABLE sessions RENAME COLUMN "UserName" TO username;
  END IF;
END $$;

-- 7. Table: trusted_devices (from "TrustedDevices")
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'TrustedDevices') THEN
    ALTER TABLE "TrustedDevices" RENAME TO trusted_devices;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'trusted_devices' AND column_name = 'UserName') THEN
    ALTER TABLE trusted_devices RENAME COLUMN "UserName" TO username;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'trusted_devices' AND column_name = 'DeviceToken') THEN
    ALTER TABLE trusted_devices RENAME COLUMN "DeviceToken" TO device_token;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'trusted_devices' AND column_name = 'DeviceName') THEN
    ALTER TABLE trusted_devices RENAME COLUMN "DeviceName" TO device_name;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'trusted_devices' AND column_name = 'UserAgent') THEN
    ALTER TABLE trusted_devices RENAME COLUMN "UserAgent" TO user_agent;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'trusted_devices' AND column_name = 'IpAddress') THEN
    ALTER TABLE trusted_devices RENAME COLUMN "IpAddress" TO ip_address;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'trusted_devices' AND column_name = 'CreatedAt') THEN
    ALTER TABLE trusted_devices RENAME COLUMN "CreatedAt" TO created_at;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'trusted_devices' AND column_name = 'ExpiresAt') THEN
    ALTER TABLE trusted_devices RENAME COLUMN "ExpiresAt" TO expires_at;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'trusted_devices' AND column_name = 'LastUsed') THEN
    ALTER TABLE trusted_devices RENAME COLUMN "LastUsed" TO last_used;
  END IF;
END $$;

-- 8. Table: two_factor (from "TwoFA")
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'TwoFA') THEN
    ALTER TABLE "TwoFA" RENAME TO two_factor;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'two_factor' AND column_name = 'UserName') THEN
    ALTER TABLE two_factor RENAME COLUMN "UserName" TO username;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'two_factor' AND column_name = 'TwoFAStatus') THEN
    ALTER TABLE two_factor RENAME COLUMN "TwoFAStatus" TO is_enabled;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'two_factor' AND column_name = 'TwoFASecret') THEN
    ALTER TABLE two_factor RENAME COLUMN "TwoFASecret" TO two_fa_secret;
  END IF;
END $$;

COMMIT;
