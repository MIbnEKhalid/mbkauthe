# GitHub Login Setup Guide

## Overview
This GitHub login feature allows users to authenticate using their GitHub account if it's already linked to their account in the system. Users must first connect their GitHub account through the regular account linking process, then they can use GitHub to log in directly.

## Setup Instructions

### 1. Environment Variables
Add these to your `.env` file:

```env
# GitHub OAuth App Configuration
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
```

### 2. GitHub OAuth App Setup
1. Go to GitHub Settings > Developer settings > OAuth Apps
2. Create a new OAuth App
3. Set the Authorization callback URL to: `https://yourdomain.com/mbkauthe/api/github/login/callback`
4. Copy the Client ID and Client Secret to your `.env` file

### 3. Database Schema
Ensure your `user_github` table exists with these columns:

```sql
CREATE TABLE user_github (
    id SERIAL PRIMARY KEY,
    user_name VARCHAR(50) REFERENCES "Users"("UserName"),
    github_id VARCHAR(255) UNIQUE,
    github_username VARCHAR(255),
    access_token VARCHAR(255),
    created_at TimeStamp WITH TIME ZONE DEFAULT NOW(),
    updated_at TimeStamp WITH TIME ZONE DEFAULT NOW()
);
```

## How It Works

### Login Flow
1. User clicks "Login with GitHub" on the login page
2. User is redirected to GitHub for authentication
3. GitHub redirects back to `/mbkauthe/api/github/login/callback`
4. System checks if the GitHub ID exists in `user_github` table
5. If found and user is active/authorized:
   - If 2FA is enabled, redirect to 2FA page
   - If no 2FA, complete login and redirect to home
6. If not found, redirect to login page with error

### Account Linking
Users must first link their GitHub account through your existing GitHub connection system (likely in user settings) before they can use GitHub login.

## API Routes Added

### `/mbkauthe/api/github/login`
- **Method**: GET
- **Description**: Initiates GitHub OAuth flow
- **Redirects to**: GitHub authorization page

### `/mbkauthe/api/github/login/callback`
- **Method**: GET
- **Description**: Handles GitHub OAuth callback
- **Parameters**: `code` (from GitHub), `state` (optional)
- **Success**: Redirects to home page or configured redirect URL
- **Error**: Redirects to login page with error parameter

## Error Handling

The system handles various error cases:
- `github_auth_failed`: GitHub OAuth failed
- `user_not_found`: GitHub account not linked to any user
- `session_error`: Session save failed
- `internal_error`: General server error

## Testing

1. Create a test user in your `Users` table
2. Link a GitHub account to that user using your existing connection system
3. Try logging in with GitHub using the new login button
4. Check console logs for debugging information

## Login Page Updates

The login page now includes:
- A "Continue with GitHub" button
- A divider ("or") between regular and GitHub login
- Proper styling that matches your existing design

## Security Notes

- Only users with active accounts can log in
- App authorization is checked (same as regular login)
- 2FA is respected if enabled
- Session management is handled the same way as regular login
- GitHub access tokens are stored securely

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
  - `Password` (TEXT): The hashed password of the user.
  - `Role` (ENUM): The role of the user. Possible values: `SuperAdmin`, `NormalUser`, `Guest`.
  - `Active` (BOOLEAN): Indicates whether the user account is active.
  - `HaveMailAccount` (BOOLEAN)(optional): Indicates if the user has a linked mail account.
  - `SessionId` (TEXT): The session ID associated with the user.
  - `GuestRole` (JSONB): Stores additional guest-specific role information in binary JSON format.
  - `AllowedApps`(JSONB): 

- **Schema:**
```sql
CREATE TYPE role AS ENUM ('SuperAdmin', 'NormalUser', 'Guest');

CREATE TABLE "Users" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    "UserName" VARCHAR(50) NOT NULL UNIQUE,
    "Password" VARCHAR(61) NOT NULL, -- For bcrypt hash
    "Role" role DEFAULT 'NormalUser' NOT NULL,
    "Active" BOOLEAN DEFAULT FALSE,
    "HaveMailAccount" BOOLEAN DEFAULT FALSE,
    "AllowedApps" JSONB DEFAULT '["mbkauthe", "portal"]',
    "SessionId" VARCHAR(213),
    "IsOnline" BOOLEAN DEFAULT FALSE,
    "created_at" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    "last_login" TIMESTAMP WITH TIME ZONE
);

-- Add indexes for Users table
CREATE INDEX IF NOT EXISTS idx_users_session_id ON "Users" ("SessionId")
CREATE INDEX idx_users_username ON "Users" USING BTREE ("UserName");
CREATE INDEX idx_users_role ON "Users" USING BTREE ("Role");
CREATE INDEX idx_users_active ON "Users" USING BTREE ("Active");
CREATE INDEX idx_users_isonline ON "Users" USING BTREE ("IsOnline");
CREATE INDEX idx_users_last_login ON "Users" USING BTREE (last_login);
```

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
    "UserName" VARCHAR(50) REFERENCES "Users"("UserName"),
    last_activity TimeStamp WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add indexes for session table
CREATE INDEX idx_session_expire ON "session" USING BTREE (expire);
CREATE INDEX idx_session_username ON "session" USING BTREE ("UserName");
CREATE INDEX idx_session_last_activity ON "session" USING BTREE (last_activity);
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

CREATE INDEX IF NOT EXISTS idx_twofa_username ON "TwoFA" ("UserName")
```

### Query to Add a User

To add new users to the `Users` table, use the following SQL queries:

```sql
        INSERT INTO "Users" ("UserName", "Password", "Role", "Active", "HaveMailAccount", "SessionId", "GuestRole")
        VALUES ('support', '12345678', 'SuperAdmin', true, false, NULL, '{"allowPages": [""], "NotallowPages": [""]}'::jsonb);

        INSERT INTO "Users" ("UserName", "Password", "Role", "Active", "HaveMailAccount", "SessionId", "GuestRole")
        VALUES ('test', '12345678', 'NormalUser', true, false, NULL, '{"allowPages": [""], "NotallowPages": [""]}'::jsonb);
```

- Replace `support` and `test` with the desired usernames.
- Replace `12345678` with the actual passwords.
- Adjust the `Role` values as needed (`SuperAdmin`, `NormalUser`, or `Guest`).
- Modify the `Active` and `HaveMailAccount` values as required.
- Update the `GuestRole` JSON object if specific permissions are required(this functionality is under construction).