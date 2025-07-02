# mbkauthe

[![Publish to npm](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/publish.yml/badge.svg?branch=main)](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/publish.yml) [![CodeQL Advanced](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/MIbnEKhalid/mbkauthe/actions/workflows/codeql.yml)

## Table of Contents

- [mbkauthe](#mbkauthe)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Implementation in a Project](#implementation-in-a-project)
    - [Basic Setup](#basic-setup)
  - [Middleware Function Documentation](#middleware-function-documentation)
    - [validateSession(session)](#validatesessionsession)
    - [checkRolePermission(userRole, requiredRoles)](#checkrolepermissionuserrole-requiredroles)
    - [validateSessionAndRole(session, userRole, requiredRoles)](#validatesessionandrolesession-userrole-requiredroles)
    - [getUserData(session)](#getuserdatasession)
    - [authenticate(session)](#authenticatesession)
  - [API Endpoints](#api-endpoints)
    - [Login](#login)
    - [Logout](#logout)
    - [Terminate All Sessions](#terminate-all-sessions)
    - [Package Information](#package-information)
    - [Version Information](#version-information)
    - [Package Lock Information](#package-lock-information)
  - [Database Structure](#database-structure)
  - [License](#license)
  - [Contact \& Support](#contact--support)

`mbkAuthe` is a reusable authentication system for Node.js applications, designed to simplify session management, user authentication, and role-based access control. It integrates seamlessly with PostgreSQL and supports features like Two-Factor Authentication (2FA) and session restoration.

## Features

- **Session Management:** Simplifies session handling with secure session restoration and expiration mechanisms.
- **User Authentication:** Provides robust authentication, including support for username/password and Two-Factor Authentication (2FA).
- **Role-Based Access Control (RBAC):** Enables fine-grained access control by validating user roles and permissions.
- **Integration with PostgreSQL:** Seamlessly integrates with PostgreSQL for user and session data storage.
- **Middleware Functions:** Includes reusable middleware for session validation, role checking, and user authentication.
- **API Endpoints:** Offers a set of RESTful APIs for login, logout, session termination, and package information retrieval.
- **Environment Configuration:** Supports flexible configuration through .env files for deployment-specific settings.
- **Demo Account:** Provides a demo account for hands-on exploration of the authentication system.
- **Database Schema:** Predefined database structure for user, session, and 2FA data management.
- **Extensibility:** Designed to be easily integrated into existing Node.js applications.
- **Secure Cookies:** Ensures secure session handling with cookie expiration and domain-specific settings

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
    "SESSION_SECRET_KEY": "your-session-secret-key",
    "IS_DEPLOYED": "true",
    "LOGIN_DB": "postgres://username:password@host:port/database",
    "MBKAUTH_TWO_FA_ENABLE": "false",
    "COOKIE_EXPIRE_TIME": 2,
    "DOMAIN": "yourdomain.com",
    "loginRedirectURL": "/admin"
}'
```

## Middleware Function Documentation

### `validateSession(session)`
Validates the user's session to ensure it is active and not expired.

- **Parameters:**
  - `session` (Object): The session object to validate.

- **Returns:**
  - `boolean`: Returns `true` if the session is valid, otherwise `false`.

Usage
```
// Require vaild session or to be login to access this page
router.get(["/home"], validateSession, (req, res) => {
  // Restricted Code
});
```

---

### `checkRolePermission(userRole, requiredRoles)`
Checks if the user has the required role permissions.

- **Parameters:**
  - `userRole` (string): The role of the user.
  - `requiredRoles`(optional) (string[]): An array of roles that are allowed access.

- **Returns:**
  - `boolean`: Returns `true` if the user has the required permissions, otherwise `false`.

Usage
```
// Require vaild session or to be login to access this page
router.get(["/admin"], validateSession, checkRolePermission("SuperAdmin"), (req, res) => {
  // Restricted Code
});
```
---

### `validateSessionAndRole(session, userRole, requiredRoles)`
Validates both the session and the user's role permissions.

- **Parameters:**
  - `session` (Object): The session object to validate.
  - `userRole` (string): The role of the user.
  - `requiredRoles` (optional) (string[]): An array of roles that are allowed access.

- **Returns:**
  - `boolean`: Returns `true` if both the session and role permissions are valid, otherwise `false`.

Usage
```
// Require vaild session or to be login to access this page
router.get(["/admin"], validateSessionAndRole("SuperAdmin"), (req, res) => {
  // Restricted Code
});
```
---

### `getUserData(session)`
Retrieves user data based on the session.

- **Parameters:**
  - `session` (Object): The session object containing user information.

- **Returns:**
  - `Object|null`: Returns the user data object if found, otherwise `null`.

---

### `authenticate(session)`
Authenticates the user by validating the session and retrieving user data.

- **Parameters:**
  - `session` (Object): The session object to authenticate.

- **Returns:**
  - `Object|null`: Returns the authenticated user data if successful, otherwise `null`.

Usage
```
// Require vaild session or to be login to access this page
router.post(["/terminateAllSessions"], authenticate(mbkautheVar.Password), (req, res) => {
  // Restricted Code
});
```



## API Endpoints

### Login

**POST** `/mbkauth/api/login`
- Request Body:
  - `username`: User's username.
  - `password`: User's password.
  - `token`: (Optional) 2FA token.

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

### Package Information

**GET** `/mbkauthe/package`

- **Description**: Retrieves the `package.json` file of the `mbkauthe` package, which contains metadata about the package, such as its name, version, dependencies, and more.
- **Response**:
  - `200`: Successfully retrieved the `package.json` file.
    - **Body**: JSON object containing the contents of the `package.json` file.
  - `500`: Internal server error.


### Version Information

**GET** `/mbkauthe/version` or `/mbkauthe/v`

- **Description**: Retrieves the current version of the `mbkauthe` package from the `package.json` file.
- **Response**:
  - `200`: Successfully retrieved the version information.
    - **Body**: JSON object containing the version, e.g., `{ "version": "1.0.0" }`.
  - `500`: Internal server error.


### Package Lock Information

**GET** `/mbkauthe/package-lock`

- **Description**: Retrieves the `package-lock.json` file from the project where the `mbkauthe` package is installed. Filters and returns only the dependency information related to `mbkauthe`, including resolved versions and integrity hashes.
- **Response**:
  - `200`: Successfully retrieved the filtered `package-lock.json` data for `mbkauthe`.
    - **Body**: JSON object containing the filtered dependency information for `mbkauthe`.
  - `500`: Internal server error.

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