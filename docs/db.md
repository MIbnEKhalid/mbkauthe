# Database Schema

This document describes the database schema used by **mbkauthe**. The schema is defined in `docs/db.sql` and is expected to match the database structure used by the application.

---

## 1. Roles

The project uses a Postgres `ENUM` type for user roles:

```sql
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'role') THEN
    CREATE TYPE role AS ENUM ('SuperAdmin', 'NormalUser', 'Guest');
  END IF;
END
$$;
```

---

## 2. Users Table

Stores user accounts and profile metadata.

```sql
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
```

### Indexes

```sql
CREATE INDEX IF NOT EXISTS idx_users_username ON "Users" USING BTREE ("UserName");
CREATE INDEX IF NOT EXISTS idx_users_role ON "Users" USING BTREE ("Role");
CREATE INDEX IF NOT EXISTS idx_users_active ON "Users" USING BTREE ("Active");
CREATE INDEX IF NOT EXISTS idx_users_email ON "Users" USING BTREE ("email");
CREATE INDEX IF NOT EXISTS idx_users_last_login ON "Users" USING BTREE (last_login);
-- JSONB GIN indexes for common filters/queries on JSON fields
CREATE INDEX IF NOT EXISTS idx_users_allowedapps_gin ON "Users" USING GIN ("AllowedApps");
CREATE INDEX IF NOT EXISTS idx_users_positions_gin ON "Users" USING GIN ("Positions");
```

### Password Storage

- `Password` is used when `EncPass=false` (plain text / legacy).
- `PasswordEnc` is used when `EncPass=true` (PBKDF2 hashed, stored as a 128-character hex string).
- Only one of the two columns should be populated depending on the configuration.


---

## 3. OAuth Link Tables (GitHub / Google)

OAuth link tables store associations between an existing user account and an OAuth provider.

### GitHub

```sql
CREATE TABLE IF NOT EXISTS user_github (
    id SERIAL PRIMARY KEY,
    user_name VARCHAR(50) REFERENCES "Users"("UserName"),
    github_id VARCHAR(255) UNIQUE,
    github_username VARCHAR(255),
    access_token TEXT,
    created_at TimeStamp WITH TIME ZONE DEFAULT NOW(),
    updated_at TimeStamp WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_github_github_id ON user_github (github_id);
CREATE INDEX IF NOT EXISTS idx_user_github_user_name ON user_github (user_name);
```

### Google

```sql
CREATE TABLE IF NOT EXISTS user_google (
    id SERIAL PRIMARY KEY,
    user_name VARCHAR(50) REFERENCES "Users"("UserName"),
    google_id VARCHAR(255) UNIQUE,
    google_email VARCHAR(255),
    access_token TEXT,
    created_at TimeStamp WITH TIME ZONE DEFAULT NOW(),
    updated_at TimeStamp WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_google_google_id ON user_google (google_id);
CREATE INDEX IF NOT EXISTS idx_user_google_user_name ON user_google (user_name);
```

---

## 4. Session Tables

### Application Sessions (`Sessions`)

Stores application sessions and supports multiple concurrent sessions per user.

```sql
CREATE TABLE IF NOT EXISTS "Sessions" (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), -- requires pgcrypto or uuid-ossp
  "UserName" VARCHAR(50) NOT NULL REFERENCES "Users"("UserName") ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE,
  meta JSONB
);

CREATE INDEX IF NOT EXISTS idx_sessions_username ON "Sessions" ("UserName");
CREATE INDEX IF NOT EXISTS idx_sessions_user_created ON "Sessions" ("UserName", created_at);
```

### Express Session Store (`session`)

Used by `express-session` when configured to store sessions in Postgres.

```sql
CREATE TABLE IF NOT EXISTS "session" (
    sid VARCHAR(33) PRIMARY KEY NOT NULL,
    sess JSONB NOT NULL,
    expire TimeStamp WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_session_expire ON "session" ("expire");
CREATE INDEX IF NOT EXISTS idx_session_user_id ON "session" ((sess->'user'->>'id'));
```

---

## 5. Two-Factor Authentication (2FA)

```sql
CREATE TABLE IF NOT EXISTS "TwoFA" (
    "UserName" VARCHAR(50) primary key REFERENCES "Users"("UserName"),
    "TwoFAStatus" boolean NOT NULL,
    "TwoFASecret" TEXT
);

CREATE INDEX IF NOT EXISTS idx_twofa_username ON "TwoFA" ("UserName");
CREATE INDEX IF NOT EXISTS idx_twofa_username_status ON "TwoFA" ("UserName", "TwoFAStatus");
```

---

## 6. Trusted Devices

Stores trusted device tokens used to remember a device and bypass 2FA challenges.

```sql
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

CREATE INDEX IF NOT EXISTS idx_trusted_devices_token ON "TrustedDevices"("DeviceToken");
CREATE INDEX IF NOT EXISTS idx_trusted_devices_username ON "TrustedDevices"("UserName");
CREATE INDEX IF NOT EXISTS idx_trusted_devices_expires ON "TrustedDevices"("ExpiresAt");
```

---

## 7. API Tokens

Stores long-lived API tokens used for programmatic access.

```sql
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

CREATE INDEX IF NOT EXISTS idx_apitokens_tokenhash 
ON "ApiTokens" ("TokenHash");

CREATE INDEX IF NOT EXISTS idx_apitokens_username 
ON "ApiTokens" ("UserName");

CREATE INDEX IF NOT EXISTS idx_apitokens_tokenhash_expires 
ON "ApiTokens" ("TokenHash", "ExpiresAt") 
WHERE "ExpiresAt" IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_apitokens_username_created 
ON "ApiTokens" ("UserName", "CreatedAt" DESC);

CREATE INDEX IF NOT EXISTS idx_apitokens_expires 
ON "ApiTokens" ("ExpiresAt") 
WHERE "ExpiresAt" IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_apitokens_permissions_gin 
ON "ApiTokens" USING GIN ("Permissions");

CREATE INDEX IF NOT EXISTS idx_apitokens_permissions_scope 
ON "ApiTokens" (("Permissions"->>'scope'));
```

### Token Permissions (JSONB)

The `Permissions` column stores both scope and allowed apps in a single JSONB structure:

```json
{
  "scope": "read-only" | "write",
  "allowedApps": null | ["app1", "app2"] | ["*"] | []
}
```

**Scope Values:**
- `read-only`: Allows only safe, read-only HTTP methods (GET, HEAD, OPTIONS)
- `write`: Allows all HTTP methods (GET, POST, PUT, DELETE, PATCH, etc.)

**AllowedApps Values:**
- `null` (default): Token inherits allowed apps from user's `AllowedApps` in Users table
- `["app1", "app2"]`: Token is restricted to specific apps (must be subset of user's apps)
- `["*"]`: Token has access to all user's apps (for non-SuperAdmin) or all apps in system (SuperAdmin only)
- `[]` (empty array): Token has no app access (effectively disabled)

**Note**: SuperAdmin users bypass all app permission checks, so their tokens work on any app regardless of the `allowedApps` value.

---

## 8. Seed Data

The schema includes a default `support` user (no encrypted password) to ensure at least one SuperAdmin account exists:

```sql
INSERT INTO "Users" ("UserName", "Password", "Role", "Active", "HaveMailAccount", "FullName")
VALUES ('support', '12345678', 'SuperAdmin', true, false, 'Support User')
ON CONFLICT ("UserName") DO NOTHING;

SELECT * FROM "Users" WHERE "UserName" = 'support';
```


- **Schema:**
```sql
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
```

### Query to Add a User

To add new users to the `Users` table, use the following SQL queries:

**For Raw Password Storage (EncPass=false):**
```sql
        INSERT INTO "Users" ("UserName", "Password", "Role", "Active", "HaveMailAccount")
        VALUES ('support', '12345678', 'SuperAdmin', true, false);

        INSERT INTO "Users" ("UserName", "Password", "Role", "Active", "HaveMailAccount")
        VALUES ('test', '12345678', 'NormalUser', true, false);
```

**For Encrypted Password Storage (EncPass=true):**
```sql
        -- Note: You'll need to hash the password using the hashPassword function
        -- Example with pre-hashed password (PBKDF2 with username as salt)
        INSERT INTO "Users" ("UserName", "PasswordEnc", "Role", "Active", "HaveMailAccount")
        VALUES ('support', 'your_hashed_password_here', 'SuperAdmin', true, false);

        INSERT INTO "Users" ("UserName", "PasswordEnc", "Role", "Active", "HaveMailAccount")
        VALUES ('test', 'your_hashed_password_here', 'NormalUser', true, false);
```

**Configuration Notes:**
- Replace `support` and `test` with the desired usernames.
- For raw passwords: Replace `12345678` with the actual plain text passwords.
- For encrypted passwords: Use the hashPassword function to generate the hash before inserting.
- Adjust the `Role` values as needed (`SuperAdmin`, `NormalUser`, or `Guest`).
- Modify the `Active` and `HaveMailAccount` values as required.

**Generating Encrypted Passwords:**
If you're using `EncPass=true`, you can generate encrypted passwords using the hashPassword function:
```javascript
import { hashPassword } from 'mbkauthe';
const encryptedPassword = hashPassword('12345678', 'support');
console.log(encryptedPassword); // Use this value for PasswordEnc column
```