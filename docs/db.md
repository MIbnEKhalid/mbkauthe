# OAuth Login Setup Guide

## Overview
This OAuth login feature allows users to authenticate using their GitHub or Google account if it's already linked to their account in the system. Users must first connect their OAuth account through the regular account linking process, then they can use it to log in directly.

## Setup Instructions

### 1. Environment Variables
Add these to your `.env` file:

```env
# GitHub OAuth App Configuration
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# Google OAuth App Configuration
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

### 2. GitHub OAuth App Setup
1. Go to GitHub Settings > Developer settings > OAuth Apps
2. Create a new OAuth App
3. Set the Authorization callback URL to: `https://yourdomain.com/mbkauthe/api/github/login/callback`
4. Copy the Client ID and Client Secret to your `.env` file

### 3. Google OAuth App Setup
1. Go to Google Cloud Console (https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API
4. Go to Credentials > Create Credentials > OAuth 2.0 Client ID
5. Set the application type to "Web application"
6. Add authorized redirect URI: `https://yourdomain.com/mbkauthe/api/google/login/callback`
7. Copy the Client ID and Client Secret to your `.env` file

### 4. Database Schema
Ensure your OAuth tables exist with these columns:

```sql
-- GitHub users table
CREATE TABLE user_github (
    id SERIAL PRIMARY KEY,
    user_name VARCHAR(50) REFERENCES "Users"("UserName"),
    github_id VARCHAR(255) UNIQUE,
    github_username VARCHAR(255),
    access_token VARCHAR(255),
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
    access_token VARCHAR(255),
    created_at TimeStamp WITH TIME ZONE DEFAULT NOW(),
    updated_at TimeStamp WITH TIME ZONE DEFAULT NOW()
);

-- Add indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_user_google_google_id ON user_google (google_id);
CREATE INDEX IF NOT EXISTS idx_user_google_user_name ON user_google (user_name);
```

## How It Works

### Login Flow (GitHub/Google)
1. User clicks "Login with GitHub" or "Login with Google" on the login page
2. User is redirected to the OAuth provider for authentication
3. Provider redirects back to `/mbkauthe/api/{provider}/login/callback`
4. System checks if the OAuth ID exists in the respective `user_{provider}` table
5. If found and user is active/authorized:
   - If 2FA is enabled, redirect to 2FA page
   - If no 2FA, complete login and redirect to home
6. If not found, redirect to login page with error

### Account Linking
Users must first link their OAuth account through your existing connection system (likely in user settings) before they can use OAuth login.

## API Routes Added

### GitHub Routes

#### `/mbkauthe/api/github/login`
- **Method**: GET
- **Description**: Initiates GitHub OAuth flow
- **Redirects to**: GitHub authorization page

#### `/mbkauthe/api/github/login/callback`
- **Method**: GET
- **Description**: Handles GitHub OAuth callback
- **Parameters**: `code` (from GitHub), `state` (optional)
- **Success**: Redirects to home page or configured redirect URL
- **Error**: Redirects to login page with error parameter

### Google Routes

#### `/mbkauthe/api/google/login`
- **Method**: GET
- **Description**: Initiates Google OAuth flow
- **Redirects to**: Google authorization page

#### `/mbkauthe/api/google/login/callback`
- **Method**: GET
- **Description**: Handles Google OAuth callback
- **Parameters**: `code` (from Google), `state` (optional)
- **Success**: Redirects to home page or configured redirect URL
- **Error**: Redirects to login page with error parameter

## Error Handling

The system handles various error cases:
- `github_auth_failed` / `google_auth_failed`: OAuth authentication failed
- `user_not_found`: OAuth account not linked to any user
- `account_inactive`: User account is deactivated
- `not_authorized`: User not authorized for this app
- `session_error`: Session save failed
- `internal_error`: General server error

## Testing

### GitHub Login
1. Create a test user in your `Users` table
2. Link a GitHub account to that user using your existing connection system
3. Try logging in with GitHub using the new login button
4. Check console logs for debugging information

### Google Login
1. Create a test user in your `Users` table
2. Link a Google account to that user using your existing connection system
3. Try logging in with Google using the new login button
4. Check console logs for debugging information

## Login Page Updates

The login page now includes:
- A "Continue with GitHub" button
- A "Continue with Google" button
- A divider ("or") between regular and OAuth login
- Proper styling that matches your existing design

## Security Notes

- Only users with active accounts can log in
- App authorization is checked (same as regular login)
- 2FA is respected if enabled
- Session management is handled the same way as regular login
- OAuth access tokens are stored securely

## Troubleshooting

1. **GitHub OAuth errors**: Check your GitHub OAuth app configuration
2. **Database errors**: Ensure `user_github` table exists and has proper relationships
3. **Session errors**: Check your session configuration
4. **2FA issues**: Verify 2FA table structure and configuration

## Environment Variables Summary

```env
# Required for GitHub Login
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
```

The GitHub login feature is now fully integrated into your mbkauthe system and ready to use!






## Database structure

[<- Back](README.md)

## Table of Contents

1. [Users Table](#users-table)
2. [Session Table](#session-table)
3. [Two-Factor Authentication Table](#two-factor-authentication-table)
4. [Query to Add a User](#query-to-add-a-user)


### Users Table

- **Columns:**

  - `id` (INTEGER, auto-increment, primary key): Unique identifier for each user.
  - `UserName` (TEXT): The username of the user.
  - `Password` (TEXT): The raw password of the user (used when EncPass=false).
  - `PasswordEnc` (TEXT): The encrypted/hashed password of the user (used when EncPass=true).
  - `Role` (ENUM): The role of the user. Possible values: `SuperAdmin`, `NormalUser`, `Guest`.
  - `Active` (BOOLEAN): Indicates whether the user account is active.
  - `HaveMailAccount` (BOOLEAN)(optional): Indicates if the user has a linked mail account.
  - `SessionId` (TEXT): The session ID associated with the user.
  - `GuestRole` (JSONB): Stores additional guest-specific role information in binary JSON format.
  - `AllowedApps`(JSONB): Array of applications the user is authorized to access.

- **Schema:**
```sql
CREATE TYPE role AS ENUM ('SuperAdmin', 'NormalUser', 'Guest');

CREATE TABLE "Users" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    "UserName" VARCHAR(50) NOT NULL UNIQUE,
    "Password" VARCHAR(61), -- For raw passwords (when EncPass=false)
    "PasswordEnc" VARCHAR(128), -- For encrypted passwords (when EncPass=true)
    "Role" role DEFAULT 'NormalUser' NOT NULL,
    "Active" BOOLEAN DEFAULT FALSE,
    "HaveMailAccount" BOOLEAN DEFAULT FALSE,
    "AllowedApps" JSONB DEFAULT '["mbkauthe", "portal"]',
    "SessionId" VARCHAR(213),
    "created_at" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    "last_login" TIMESTAMP WITH TIME ZONE
);

-- Add indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_users_sessionid ON "Users" (LOWER("SessionId"));
CREATE INDEX IF NOT EXISTS idx_users_username ON "Users" ("UserName");
CREATE INDEX IF NOT EXISTS idx_users_active ON "Users" ("Active");
CREATE INDEX IF NOT EXISTS idx_users_role ON "Users" ("Role");
CREATE INDEX IF NOT EXISTS idx_users_last_login ON "Users" (last_login);
CREATE INDEX IF NOT EXISTS idx_users_id_sessionid_active_role ON "Users" ("id", LOWER("SessionId"), "Active", "Role");
```

**Password Storage Notes:**
- When `EncPass=false` (default): The system uses the `Password` column to store and validate raw passwords
- When `EncPass=true` (recommended for production): The system uses the `PasswordEnc` column to store hashed passwords using PBKDF2 with the username as salt
- Only one password column should be populated based on your EncPass configuration
- The PasswordEnc field stores 128-character hex strings when using PBKDF2 hashing

### Session Table

- **Columns:**

  - `sid` (VARCHAR, primary key): Unique session identifier.
  - `sess` (JSON): Session data stored in JSON format.
  - `expire` (TIMESTAMP): Expiration timestamp for the session.

- **Schema:**
```sql
CREATE TABLE "session" (
    sid VARCHAR(33) PRIMARY KEY NOT NULL,
    sess JSONB NOT NULL,
    expire TimeStamp WITH TIME ZONE Not Null,
    last_activity TimeStamp WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_session_expire ON "session" ("expire");
CREATE INDEX IF NOT EXISTS idx_session_last_activity ON "session" (last_activity);
CREATE INDEX IF NOT EXISTS idx_session_user_id ON "session" ((sess->'user'->>'id'));
```

### Two-Factor Authentication Table

- **Columns:**

  - `UserName` (TEXT): The username of the user.
  - `TwoFAStatus` (TEXT): The status of two-factor authentication (e.g., enabled, disabled).
  - `TwoFASecret` (TEXT): The secret key used for two-factor authentication.

- **Schema:**
```sql
CREATE TABLE "TwoFA" (
    "UserName" VARCHAR(50) primary key REFERENCES "Users"("UserName"),
    "TwoFAStatus" boolean NOT NULL,
    "TwoFASecret" TEXT
);

-- Add indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_twofa_username ON "TwoFA" ("UserName");
CREATE INDEX IF NOT EXISTS idx_twofa_username_status ON "TwoFA" ("UserName", "TwoFAStatus");
```

### Trusted Devices Table (Remember 2FA Device)

- **Columns:**

  - `id` (INTEGER, auto-increment, primary key): Unique identifier for each trusted device.
  - `UserName` (VARCHAR): The username of the device owner (foreign key to Users).
  - `DeviceToken` (VARCHAR): Unique token identifying the trusted device.
  - `DeviceName` (VARCHAR): Optional friendly name for the device.
  - `UserAgent` (TEXT): Browser/client user agent string.
  - `IpAddress` (VARCHAR): IP address when device was trusted.
  - `CreatedAt` (TIMESTAMP): When the device was first trusted.
  - `ExpiresAt` (TIMESTAMP): When the device trust expires.
  - `LastUsed` (TIMESTAMP): Last time this device was used for login.

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
        INSERT INTO "Users" ("UserName", "Password", "Role", "Active", "HaveMailAccount", "SessionId", "GuestRole")
        VALUES ('support', '12345678', 'SuperAdmin', true, false, NULL, '{"allowPages": [""], "NotallowPages": [""]}'::jsonb);

        INSERT INTO "Users" ("UserName", "Password", "Role", "Active", "HaveMailAccount", "SessionId", "GuestRole")
        VALUES ('test', '12345678', 'NormalUser', true, false, NULL, '{"allowPages": [""], "NotallowPages": [""]}'::jsonb);
```

**For Encrypted Password Storage (EncPass=true):**
```sql
        -- Note: You'll need to hash the password using the hashPassword function
        -- Example with pre-hashed password (PBKDF2 with username as salt)
        INSERT INTO "Users" ("UserName", "PasswordEnc", "Role", "Active", "HaveMailAccount", "SessionId", "GuestRole")
        VALUES ('support', 'your_hashed_password_here', 'SuperAdmin', true, false, NULL, '{"allowPages": [""], "NotallowPages": [""]}'::jsonb);

        INSERT INTO "Users" ("UserName", "PasswordEnc", "Role", "Active", "HaveMailAccount", "SessionId", "GuestRole")
        VALUES ('test', 'your_hashed_password_here', 'NormalUser', true, false, NULL, '{"allowPages": [""], "NotallowPages": [""]}'::jsonb);
```

**Configuration Notes:**
- Replace `support` and `test` with the desired usernames.
- For raw passwords: Replace `12345678` with the actual plain text passwords.
- For encrypted passwords: Use the hashPassword function to generate the hash before inserting.
- Adjust the `Role` values as needed (`SuperAdmin`, `NormalUser`, or `Guest`).
- Modify the `Active` and `HaveMailAccount` values as required.
- Update the `GuestRole` JSON object if specific permissions are required (this functionality is under construction).

**Generating Encrypted Passwords:**
If you're using `EncPass=true`, you can generate encrypted passwords using the hashPassword function:
```javascript
import { hashPassword } from 'mbkauthe';
const encryptedPassword = hashPassword('12345678', 'support');
console.log(encryptedPassword); // Use this value for PasswordEnc column
```