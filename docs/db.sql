
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'role') THEN
    CREATE TYPE role AS ENUM ('SuperAdmin', 'NormalUser', 'Guest');
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS "Users" (
    id SERIAL PRIMARY KEY,
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
    "Image" TEXT DEFAULT 'https://portal.mbktech.org/Assets/Images/M.png',
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

-- OAuth user tables (depend on "Users")
-- GitHub users table
CREATE TABLE IF NOT EXISTS user_github (
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
CREATE TABLE IF NOT EXISTS user_google (
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


-- Application Sessions table (stores multiple concurrent sessions per user)
-- Note: this is separate from the express-session store table named "session"
CREATE TABLE IF NOT EXISTS "Sessions" (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), -- requires pgcrypto or uuid-ossp
  "UserName" VARCHAR(50) NOT NULL REFERENCES "Users"("UserName") ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE,
    meta JSONB
);

-- Indexes optimized by username instead of numeric user id
CREATE INDEX IF NOT EXISTS idx_sessions_username ON "Sessions" ("UserName");
CREATE INDEX IF NOT EXISTS idx_sessions_user_created ON "Sessions" ("UserName", created_at);


CREATE TABLE IF NOT EXISTS "session" (
    sid VARCHAR(33) PRIMARY KEY NOT NULL,
    sess JSONB NOT NULL,
    expire TimeStamp WITH TIME ZONE NOT NULL,
    username TEXT,
    last_activity TimeStamp WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_session_expire ON "session" ("expire");
CREATE INDEX IF NOT EXISTS idx_session_user_id ON "session" ((sess->'user'->>'id'));



CREATE TABLE IF NOT EXISTS "TwoFA" (
    "UserName" VARCHAR(50) primary key REFERENCES "Users"("UserName"),
    "TwoFAStatus" boolean NOT NULL,
    "TwoFASecret" TEXT
);

-- Add indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_twofa_username ON "TwoFA" ("UserName");
CREATE INDEX IF NOT EXISTS idx_twofa_username_status ON "TwoFA" ("UserName", "TwoFAStatus");



CREATE TABLE IF NOT EXISTS "TrustedDevices" (
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
INSERT INTO "Users" ("UserName", "Password", "Role", "Active", "HaveMailAccount", "FullName")
VALUES ('support', '12345678', 'SuperAdmin', true, false, 'Support User')
ON CONFLICT ("UserName") DO NOTHING;

SELECT * FROM "Users" WHERE "UserName" = 'support';

-- API Tokens for persistent programmatic access
CREATE TABLE IF NOT EXISTS "ApiTokens" (
    "id" SERIAL PRIMARY KEY,
    "UserName" VARCHAR(50) NOT NULL REFERENCES "Users"("UserName") ON DELETE CASCADE,
    "Name" VARCHAR(255) NOT NULL CHECK (LENGTH(TRIM("Name")) > 0),
    "TokenHash" VARCHAR(128) NOT NULL UNIQUE,
    "Prefix" VARCHAR(32) NOT NULL,
    "Permissions" JSONB NOT NULL DEFAULT '{"scope":"read-only","allowedApps":null}'::jsonb
        CHECK ("Permissions"->>'scope' IN ('read-only', 'write')),
    "LastUsed" TIMESTAMP WITH TIME ZONE,
    "CreatedAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    "ExpiresAt" TIMESTAMP WITH TIME ZONE
        CHECK ("ExpiresAt" IS NULL OR "ExpiresAt" > "CreatedAt")
);

-- Basic indexes
CREATE INDEX IF NOT EXISTS idx_apitokens_tokenhash 
ON "ApiTokens" ("TokenHash");

CREATE INDEX IF NOT EXISTS idx_apitokens_username 
ON "ApiTokens" ("UserName");

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_apitokens_tokenhash_expires 
ON "ApiTokens" ("TokenHash", "ExpiresAt") 
WHERE "ExpiresAt" IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_apitokens_username_created 
ON "ApiTokens" ("UserName", "CreatedAt" DESC);

CREATE INDEX IF NOT EXISTS idx_apitokens_expires 
ON "ApiTokens" ("ExpiresAt") 
WHERE "ExpiresAt" IS NOT NULL;

-- JSONB indexes for fast permission queries
CREATE INDEX IF NOT EXISTS idx_apitokens_permissions_gin 
ON "ApiTokens" USING GIN ("Permissions");

CREATE INDEX IF NOT EXISTS idx_apitokens_permissions_scope 
ON "ApiTokens" (("Permissions"->>'scope'));













-- WebPortal user table

-- todos table for user tasks, with indexes for performance optimization
CREATE TABLE IF NOT EXISTS "todos" (
    "id" SERIAL PRIMARY KEY,
    "username" VARCHAR(50) NOT NULL REFERENCES "Users"("UserName"),
    "title" VARCHAR(255) NOT NULL,
    "description" TEXT,
    "completed" BOOLEAN DEFAULT false,
    "type" VARCHAR(20) DEFAULT 'personal' CHECK ("type" IN ('personal', 'admin')),
    "assigned" BOOLEAN DEFAULT false,
    "assigneduser" VARCHAR(50) DEFAULT 'none',
    "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_todos_username ON "todos" USING BTREE ("username");
CREATE INDEX IF NOT EXISTS idx_todos_type ON "todos" USING BTREE ("type");
CREATE INDEX IF NOT EXISTS idx_todos_completed ON "todos" USING BTREE ("completed");
CREATE INDEX IF NOT EXISTS idx_todos_type_completed ON "todos" USING BTREE ("type", "completed");
CREATE INDEX IF NOT EXISTS idx_todos_assigned ON "todos" USING BTREE ("assigned");
CREATE INDEX IF NOT EXISTS idx_todos_assigneduser ON "todos" USING BTREE ("assigneduser");
CREATE INDEX IF NOT EXISTS idx_todos_username_type ON "todos" USING BTREE ("username", "type");
CREATE INDEX IF NOT EXISTS idx_todos_title ON "todos" USING BTREE ("title");
CREATE INDEX IF NOT EXISTS idx_todos_description ON "todos" USING BTREE ("description");





-- Plan upgrade requests table
CREATE TABLE IF NOT EXISTS plan_upgrade_requests (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) REFERENCES "Users"("UserName"),
    curr_role VARCHAR(50) NOT NULL,
    requested_plan VARCHAR(50) NOT NULL,
    req_role VARCHAR(50) NOT NULL,
    reason TEXT NOT NULL,
    experience TEXT,
    portfolio VARCHAR(500),
    linkedin VARCHAR(500),
    github VARCHAR(500),
    additional_info TEXT,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    admin_notes TEXT,
    reviewed_by VARCHAR(255),
    created_at TimeStamp WITH TIME ZONE DEFAULT NOW(),
    updated_at TimeStamp WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_username ON plan_upgrade_requests("username");
CREATE INDEX IF NOT EXISTS idx_status ON plan_upgrade_requests(status);
CREATE INDEX IF NOT EXISTS idx_created_at ON plan_upgrade_requests(created_at);
CREATE INDEX IF NOT EXISTS idx_requested_plan ON plan_upgrade_requests(requested_plan);
CREATE INDEX IF NOT EXISTS idx_status_created_at ON plan_upgrade_requests(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_username_status ON plan_upgrade_requests("username", status);
CREATE INDEX IF NOT EXISTS idx_req_role_status ON plan_upgrade_requests("req_role", status);