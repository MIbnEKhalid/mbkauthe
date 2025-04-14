# mbkauthe

[![Publish to npm](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/publish.yml/badge.svg?branch=main)](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/publish.yml) [![CodeQL Advanced](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/codeql.yml)

## Table of Contents

- [Introduction](#mbkauth)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Implementation in a Project](#implementation-in-a-project)
  - [Basic Setup](#basic-setup)
- [API Endpoints](#api-endpoints)
  - [Login](#login)
  - [Logout](#logout)
  - [Terminate All Sessions](#terminate-all-sessions)
- [Database Structure](#database-structure)
- [License](#license)
- [Contact & Support](#contact--support)

`mbkAuthe` is a reusable authentication system for Node.js applications, designed to simplify session management, user authentication, and role-based access control. It integrates seamlessly with PostgreSQL and supports features like Two-Factor Authentication (2FA), session restoration, and reCAPTCHA verification.

## Features

- **Session Management**: Secure session handling using `express-session` and `connect-pg-simple`.
- **Role-Based Access Control**: Validate user roles and permissions with ease.
- **Two-Factor Authentication (2FA)**: Optional 2FA support for enhanced security.
- **reCAPTCHA Integration**: Protect login endpoints with Google reCAPTCHA.
- **Cookie Management**: Configurable cookie expiration and domain settings.
- **PostgreSQL Integration**: Uses a connection pool for efficient database interactions.

## Installation

Install the package via npm:

```bash
npm install mbkauthe
```

## Usage

### Implementation in a Project

For a practical example of how to use this package, check out the [ProjectImplementation branch](https://github.com/MIbnEKhalid/mbkauthe/tree/ProjectImplementation) of the repository. This branch demonstrates the integration of the package, including a login page, a protected page, and logout functionality.

You can explore the functionality of `mbkAuthe` using the following demo account on [mbkauthe.mbktechstudio.com](https://mbkauthe.mbktechstudio.com):

- **Username**: `demo`
- **Password**: `demo`

This demo provides a hands-on experience with the authentication system, including login, session management, and other features.

### Basic Setup
1. Import and configure the router in your Express application:
```javascript
import express from "express";
import mbkAuthRouter from "mbkauthe";

const app = express();

app.use(mbkAuthRouter);

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
```
2. Ensure your `.env` file is properly configured. Refer to the [Configuration Guide(env.md)](env.md) for details.

Example `.env` file:
```code
mbkautheVar='{
    "APP_NAME": "MBKAUTH",
    "RECAPTCHA_SECRET_KEY": "your-recaptcha-secret-key",
    "RECAPTCHA_Enabled": "false",
    "BypassUsers": ["user1","user2"],
    "SESSION_SECRET_KEY": "your-session-secret-key",
    "IS_DEPLOYED": "true",
    "LOGIN_DB": "postgres://username:password@host:port/database",
    "MBKAUTH_TWO_FA_ENABLE": "false",
    "COOKIE_EXPIRE_TIME": "1",
    "DOMAIN": "yourdomain.com"
}'
```

## API Endpoints

### Login

**POST** `/mbkauth/api/login`
- Request Body:
  - `username`: User's username.
  - `password`: User's password.
  - `token`: (Optional) 2FA token.
  - `recaptcha`: reCAPTCHA response.

- Response:
  - `200`: Login successful.
  - `400`: Missing or invalid input.
  - `401`: Unauthorized (e.g., invalid credentials or 2FA token).
  - `500`: Internal server error.

### Logout

**POST** `/mbkauth/api/logout`
- Response:
  - `200`: Login successful.
  - `400`: User not logged in.
  - `500`: Internal server error.

### Terminate All Sessions

**POST** `/mbkauth/api/terminateAllSessions`
- Authentication: Requires a valid `Main_SECRET_TOKEN` in the `Authorization` header.
- Response:
  - `200`: All sessions terminated successfully.
  - `500`: Internal server error.
  - 
  

## Database Structure

This project utilizes three primary tables:

1. **User**: Stores the main user information.
2. **sess**: Contains session-related data for users.
3. **TwoFA**: Saves the Two-Factor Authentication (2FA) secrets for users.

For detailed information about table columns, schema, and queries to create these tables, refer to the [Database Guide (docs/db.md)](docs/db.md).

## License
This project is licensed under the `Mozilla Public License 2.0`. See the [LICENSE](./LICENSE) file for details.



## Contact & Support

For questions or contributions, please contact Muhammad Bin Khalid at [mbktechstudio.com/Support](https://mbktechstudio.com/Support/), [support@mbktechstudio.com](mailto:support@mbktechstudio.com) or [chmuhammadbinkhalid28.com](mailto:chmuhammadbinkhalid28.com). 

**Developed by [Muhammad Bin Khalid](https://github.com/MIbnEKhalid)**