
-- GitHub users table
CREATE TABLE user_github (
    id SERIAL PRIMARY KEY,
    user_name VARCHAR(50) REFERENCES "Users"("UserName"),
    github_id VARCHAR(255) UNIQUE,
    github_username VARCHAR(255),
    access_token TEXT,
    created_at TimeStamp WITH TIME ZONE DEFAULT NOW(),
    updated_at TimeStamp WITH TIME ZONE DEFAULT NOW()
);

-- Add indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_user_github_github_id ON user_github (github_id);
CREATE INDEX IF NOT EXISTS idx_user_github_user_name ON user_github (user_name);

-- Google users table
CREATE TABLE user_google (
    id SERIAL PRIMARY KEY,
    user_name VARCHAR(50) REFERENCES "Users"("UserName"),
    google_id VARCHAR(255) UNIQUE,
    google_email VARCHAR(255),
    access_token TEXT,
    created_at TimeStamp WITH TIME ZONE DEFAULT NOW(),
    updated_at TimeStamp WITH TIME ZONE DEFAULT NOW()
);

-- Add indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_user_google_google_id ON user_google (google_id);
CREATE INDEX IF NOT EXISTS idx_user_google_user_name ON user_google (user_name);




CREATE TYPE role AS ENUM ('SuperAdmin', 'NormalUser', 'Guest');


CREATE TABLE "Users" (
    id INTEGER PRIMARY KEY AUTOINCREMENT AS IDENTITY,
    "UserName" VARCHAR(50) NOT NULL UNIQUE,
    "Password" VARCHAR(255) NOT NULL,
    "Active" BOOLEAN DEFAULT FALSE,
    "Role" role DEFAULT 'NormalUser' NOT NULL,
    "HaveMailAccount" BOOLEAN DEFAULT FALSE,
    "AllowedApps" JSONB DEFAULT '["mbkauthe", "portal"]',
    "created_at" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    "last_login" TIMESTAMP WITH TIME ZONE,
    "PasswordEnc" VARCHAR(128),
    
    "FullName" VARCHAR(255),
    "email" TEXT DEFAULT 'support@mbktech.org',
    "Image" TEXT DEFAULT 'https://portal.mbktech.org/icon.svg',
    "Bio" TEXT DEFAULT 'I am ....',
    "SocialAccounts" TEXT DEFAULT '{}',
    "Positions" jsonb DEFAULT '{"Not_Permanent":"Member Is Not Permanent"}',
    "resetToken" TEXT,
    "resetTokenExpires" TimeStamp,
    "resetAttempts" INTEGER DEFAULT '0',
    "lastResetAttempt" TimeStamp WITH TIME ZONE
);


CREATE INDEX IF NOT EXISTS idx_users_username ON "Users" USING BTREE ("UserName");
CREATE INDEX IF NOT EXISTS idx_users_role ON "Users" USING BTREE ("Role");
CREATE INDEX IF NOT EXISTS idx_users_active ON "Users" USING BTREE ("Active");
CREATE INDEX IF NOT EXISTS idx_users_email ON "Users" USING BTREE ("email");
CREATE INDEX IF NOT EXISTS idx_users_last_login ON "Users" USING BTREE (last_login);
-- JSONB GIN indexes for common filters/queries on JSON fields
CREATE INDEX IF NOT EXISTS idx_users_allowedapps_gin ON "Users" USING GIN ("AllowedApps");
CREATE INDEX IF NOT EXISTS idx_users_positions_gin ON "Users" USING GIN ("Positions");

-- Application Sessions table (stores multiple concurrent sessions per user)
-- Note: this is separate from the express-session store table named "session"
CREATE TABLE "Sessions" (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), -- requires pgcrypto or uuid-ossp
  "UserName" VARCHAR(50) NOT NULL REFERENCES "Users"("UserName") ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE,
    meta JSONB
);

-- Indexes optimized by username instead of numeric user id
CREATE INDEX IF NOT EXISTS idx_sessions_username ON "Sessions" ("UserName");
CREATE INDEX IF NOT EXISTS idx_sessions_user_created ON "Sessions" ("UserName", created_at);


CREATE TABLE "session" (
    sid VARCHAR(33) PRIMARY KEY NOT NULL,
    sess JSONB NOT NULL,
    expire TimeStamp WITH TIME ZONE Not Null,
);

-- Add indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_session_expire ON "session" ("expire");
CREATE INDEX IF NOT EXISTS idx_session_user_id ON "session" ((sess->'user'->>'id'));



CREATE TABLE "TwoFA" (
    "UserName" VARCHAR(50) primary key REFERENCES "Users"("UserName"),
    "TwoFAStatus" boolean NOT NULL,
    "TwoFASecret" TEXT
);

-- Add indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_twofa_username ON "TwoFA" ("UserName");
CREATE INDEX IF NOT EXISTS idx_twofa_username_status ON "TwoFA" ("UserName", "TwoFAStatus");



CREATE TABLE "TrustedDevices" (
    "id" SERIAL PRIMARY KEY,
    "UserName" VARCHAR(50) NOT NULL REFERENCES "Users"("UserName") ON DELETE CASCADE,
    "DeviceToken" VARCHAR(64) UNIQUE NOT NULL,
    "DeviceName" VARCHAR(255),
    "UserAgent" TEXT,
    "IpAddress" VARCHAR(45),
    "CreatedAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    "ExpiresAt" TIMESTAMP WITH TIME ZONE NOT NULL,
    "LastUsed" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_trusted_devices_token ON "TrustedDevices"("DeviceToken");
CREATE INDEX IF NOT EXISTS idx_trusted_devices_username ON "TrustedDevices"("UserName");
CREATE INDEX IF NOT EXISTS idx_trusted_devices_expires ON "TrustedDevices"("ExpiresAt");


-- No Encrypted password for 'support' user
INSERT INTO "Users" ("UserName", "Password", "Role", "Active", "HaveMailAccount", "GuestRole")
        VALUES ('support', '12345678', 'SuperAdmin', true, false, '{"allowPages": [""], "NotallowPages": [""]}'::jsonb);
