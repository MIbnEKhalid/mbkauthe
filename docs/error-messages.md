# Error Messages & Codes

MBKAuthe provides a comprehensive error messaging system with standardized error codes and user-friendly messages.

## Overview

The error messaging system provides:
- **Standardized Error Codes**: Consistent error codes across all operations
- **User-Friendly Messages**: Clear, actionable error messages for end users
- **Developer Context**: Detailed error information for logging and debugging
- **Helpful Hints**: Guidance on how to resolve errors
- **Structured Responses**: Consistent error response format
- **Dynamic Documentation**: Error code page at `/mbkauthe/ErrorCode` auto-generates from `lib/utils/errors.js`

## Dynamic Error Documentation

The error code documentation page (`/mbkauthe/ErrorCode`) is **automatically generated** from the `lib/utils/errors.js` file. This ensures the documentation is always in sync with the actual error codes in the system.

### Adding New Errors

To add a new error code:

1. **Define the error code** in `ErrorCodes` enum:
```javascript
export const ErrorCodes = {
    // ... existing codes
    YOUR_NEW_ERROR: 1400,
};
```

2. **Add error details** to `ErrorMessages` object:
```javascript
export const ErrorMessages = {
    // ... existing messages
    [ErrorCodes.YOUR_NEW_ERROR]: {
        message: "Internal message for logging",
        userMessage: "User-friendly error message",
        hint: "Helpful tip to resolve the issue"
    },
};
```

3. **Include in category array** in `misc.js` route handler:
```javascript
const categories = [
    // ... existing categories
    {
        name: "Your Category Name",
        range: "1400-1499",
        codes: [1400, 1401, 1402] // Add your new codes here
    }
];
```

The error code page will automatically display your new error without any additional changes.

## Error Code Ranges

| Range | Category | Example |
|-------|----------|---------|
| 600-699 | Authentication | Invalid credentials, account inactive |
| 700-799 | Two-Factor Authentication | Invalid 2FA token, 2FA not configured |
| 800-899 | Session Management | Session expired, invalid session |
| 900-999 | Authorization | Insufficient permissions, role not allowed |
| 1000-1099 | Input Validation | Missing fields, invalid format |
| 1100-1199 | Rate Limiting | Too many requests |
| 1200-1299 | Server Errors | Internal error, database error |
| 1300-1399 | OAuth | GitHub not linked, OAuth failed |

## Error Codes Reference

### Authentication Errors (600-699)

#### `601 - INVALID_CREDENTIALS`
General authentication failure.
```javascript
{
    errorCode: 601,
    message: "The username or password you entered is incorrect. Please try again.",
    hint: "Check your spelling and make sure Caps Lock is off"
}
```

#### `602 - USER_NOT_FOUND`
User account doesn't exist.
```javascript
{
    errorCode: 602,
    message: "We couldn't find an account with that username.",
    hint: "Please check the username and try again"
}
```

#### `603 - INCORRECT_PASSWORD`
Password doesn't match.
```javascript
{
    errorCode: 603,
    message: "The password you entered is incorrect.",
    hint: "Make sure you're using the correct password for this account"
}
```

#### `604 - ACCOUNT_INACTIVE`
User account is deactivated.
```javascript
{
    errorCode: 604,
    message: "Your account has been deactivated.",
    hint: "Please contact your administrator to reactivate your account"
}
```

#### `605 - APP_NOT_AUTHORIZED`
User not authorized for this application.
```javascript
{
    errorCode: 605,
    message: "You don't have permission to access this application.",
    hint: "Contact your administrator if you believe this is an error"
}
```

### 2FA Errors (700-799)

#### `701 - TWO_FA_REQUIRED`
2FA verification needed.

#### `702 - TWO_FA_INVALID_TOKEN`
Invalid 2FA code.

#### `703 - TWO_FA_NOT_CONFIGURED`
2FA not set up.

#### `704 - TWO_FA_EXPIRED`
2FA code has expired.

### Session Errors (800-899)

#### `801 - SESSION_EXPIRED`
Session has expired.

#### `802 - SESSION_INVALID`
Session is no longer valid.

#### `803 - SESSION_NOT_FOUND`
No active session found.

### Authorization Errors (900-999)

#### `901 - INSUFFICIENT_PERMISSIONS`
User lacks required permissions.

#### `902 - ROLE_NOT_ALLOWED`
User's role doesn't have access.

### Input Validation Errors (1000-1099)

#### `1001 - MISSING_REQUIRED_FIELD`
Required field not provided.

#### `1002 - INVALID_USERNAME_FORMAT`
Username format is invalid.

#### `1003 - INVALID_PASSWORD_LENGTH`
Password doesn't meet length requirements.

#### `1004 - INVALID_TOKEN_FORMAT`
Token format is incorrect.

### Rate Limiting (1100-1199)

#### `1101 - RATE_LIMIT_EXCEEDED`
Too many requests in time window.

### Server Errors (1200-1299)

#### `1201 - INTERNAL_SERVER_ERROR`
General server error.

#### `1202 - DATABASE_ERROR`
Database operation failed.

#### `1203 - CONFIGURATION_ERROR`
System configuration issue.

### OAuth Errors (1300-1399)

#### `1301 - GITHUB_NOT_LINKED`
GitHub account not linked.

#### `1302 - GITHUB_AUTH_FAILED`
GitHub authentication failed.

#### `1303 - OAUTH_STATE_MISMATCH`
OAuth state verification failed.

## API Usage

### Import Error Utilities

```javascript
import { 
    ErrorCodes, 
    ErrorMessages, 
    getErrorByCode, 
    createErrorResponse, 
    logError 
} from 'mbkauthe';
```

### Get Error Details

```javascript
import { getErrorByCode, ErrorCodes } from 'mbkauthe';

const error = getErrorByCode(ErrorCodes.INVALID_CREDENTIALS);

console.log(error);
// {
//     errorCode: 601,
//     message: "Invalid username or password",
//     userMessage: "The username or password you entered is incorrect...",
//     hint: "Check your spelling and make sure Caps Lock is off"
// }
```

### Create Error Response

```javascript
import { createErrorResponse, ErrorCodes } from 'mbkauthe';

app.post('/login', async (req, res) => {
    // ... authentication logic
    
    if (!authenticated) {
        return res.status(401).json(
            createErrorResponse(401, ErrorCodes.INVALID_CREDENTIALS)
        );
    }
});

// Response:
// {
//     success: false,
//     statusCode: 401,
//     errorCode: 601,
//     message: "The username or password you entered is incorrect...",
//     hint: "Check your spelling and make sure Caps Lock is off",
//     timestamp: "2025-12-03T12:00:00.000Z"
// }
```

### Add Custom Data

```javascript
import { createErrorResponse, ErrorCodes } from 'mbkauthe';

return res.status(403).json(
    createErrorResponse(403, ErrorCodes.APP_NOT_AUTHORIZED, {
        appName: 'Admin Panel',
        requiredRole: 'SuperAdmin'
    })
);

// Response includes custom data:
// {
//     success: false,
//     statusCode: 403,
//     errorCode: 605,
//     message: "You don't have permission to access this application.",
//     hint: "Contact your administrator if you believe this is an error",
//     timestamp: "2025-12-03T12:00:00.000Z",
//     appName: "Admin Panel",
//     requiredRole: "SuperAdmin"
// }
```

### Log Errors

```javascript
import { logError, ErrorCodes } from 'mbkauthe';

// Log error with context
logError('Login attempt', ErrorCodes.INVALID_CREDENTIALS, {
    username: 'john.doe',
    ip: req.ip,
    userAgent: req.headers['user-agent']
});

// Console output:
// [mbkauthe] Login attempt: {
//     errorCode: 601,
//     message: 'Invalid username or password',
//     username: 'john.doe',
//     ip: '192.168.1.1',
//     userAgent: 'Mozilla/5.0...',
//     timestamp: '2025-12-03T12:00:00.000Z'
// }
```

## Error Response Format

All error responses follow this structure:

```typescript
{
    success: false,
    statusCode: number,
    errorCode: number,
    message: string,        // User-friendly message
    hint: string,           // How to resolve the error
    timestamp: string,      // ISO 8601 timestamp
    ...customFields         // Optional custom data
}
```

## Client-Side Error Handling

### JavaScript Example

```javascript
async function login(username, password) {
    try {
        const response = await fetch('/mbkauthe/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            // Handle error based on error code
            switch (data.errorCode) {
                case 601: // INVALID_CREDENTIALS
                case 602: // USER_NOT_FOUND
                case 603: // INCORRECT_PASSWORD
                    showError('Invalid username or password', data.hint);
                    break;
                    
                case 604: // ACCOUNT_INACTIVE
                    showError('Account deactivated', data.hint);
                    break;
                    
                case 605: // APP_NOT_AUTHORIZED
                    showError('Access denied', data.hint);
                    redirectToHome();
                    break;
                    
                case 1003: // INVALID_PASSWORD_LENGTH
                    showFieldError('password', data.message, data.hint);
                    break;
                    
                default:
                    showError(data.message, data.hint);
            }
            return;
        }
        
        // Handle successful login
        if (data.twoFactorRequired) {
            redirectTo2FA();
        } else {
            redirectToDashboard();
        }
        
    } catch (error) {
        showError('Network error', 'Please check your connection and try again');
    }
}

function showError(message, hint) {
    const errorDiv = document.getElementById('error-message');
    errorDiv.innerHTML = `
        <div class="error">
            <strong>${message}</strong>
            <p>${hint}</p>
        </div>
    `;
}
```

### React Example

```jsx
import { ErrorCodes } from 'mbkauthe';

function LoginForm() {
    const [error, setError] = useState(null);
    
    const handleLogin = async (e) => {
        e.preventDefault();
        
        try {
            const response = await fetch('/mbkauthe/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                setError({
                    code: data.errorCode,
                    message: data.message,
                    hint: data.hint
                });
                return;
            }
            
            // Success handling...
            
        } catch (err) {
            setError({
                message: 'Network error',
                hint: 'Please check your connection'
            });
        }
    };
    
    return (
        <form onSubmit={handleLogin}>
            {error && (
                <div className="alert alert-danger">
                    <strong>{error.message}</strong>
                    {error.hint && <p className="hint">{error.hint}</p>}
                </div>
            )}
            {/* Form fields... */}
        </form>
    );
}
```

## Custom Error Messages

You can create custom error responses while maintaining the standard format:

```javascript
import { createErrorResponse } from 'mbkauthe';

app.post('/custom-action', validateSession, async (req, res) => {
    try {
        // Your logic...
        
        if (someCondition) {
            return res.status(400).json(
                createErrorResponse(400, 9999, {
                    message: "Custom error message",
                    hint: "How to fix this issue",
                    additionalData: "Extra context"
                })
            );
        }
        
    } catch (error) {
        return res.status(500).json(
            createErrorResponse(500, 1201)
        );
    }
});
```

## Best Practices

1. **Use Error Codes**: Always use predefined error codes for consistency
2. **Log Errors**: Use `logError()` for server-side logging
3. **User-Friendly Messages**: Display `message` to users, not raw error codes
4. **Provide Hints**: Show `hint` to guide users on resolution
5. **Don't Expose Internals**: Avoid exposing system details in production
6. **Handle All Cases**: Have fallback error handling for unexpected errors
7. **Client-Side Validation**: Validate input before sending to prevent unnecessary errors
8. **Structured Logging**: Include context (username, IP, etc.) in logs

## Security Considerations

1. **Generic Messages**: For authentication, use generic messages to avoid user enumeration
2. **Rate Limiting**: Implement rate limiting to prevent brute force
3. **Logging**: Log all authentication failures for security monitoring
4. **Error Details**: Only expose detailed errors in development, not production
5. **Sensitive Data**: Never include passwords or tokens in error logs

## Examples

### Complete Login with Error Handling

```javascript
router.post('/mbkauthe/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    try {
        // Validation
        if (!username || !password) {
            logError('Login', ErrorCodes.MISSING_REQUIRED_FIELD);
            return res.status(400).json(
                createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD)
            );
        }
        
        if (username.length > 255) {
            logError('Login', ErrorCodes.INVALID_USERNAME_FORMAT, { username });
            return res.status(400).json(
                createErrorResponse(400, ErrorCodes.INVALID_USERNAME_FORMAT)
            );
        }
        
        if (password.length < 8) {
            logError('Login', ErrorCodes.INVALID_PASSWORD_LENGTH);
            return res.status(400).json(
                createErrorResponse(400, ErrorCodes.INVALID_PASSWORD_LENGTH)
            );
        }
        
        // Authentication
        const user = await findUser(username);
        
        if (!user) {
            logError('Login', ErrorCodes.USER_NOT_FOUND, { username });
            // Use generic message for security
            return res.status(401).json(
                createErrorResponse(401, ErrorCodes.INVALID_CREDENTIALS)
            );
        }
        
        if (!await verifyPassword(password, user.password)) {
            logError('Login', ErrorCodes.INCORRECT_PASSWORD, { username });
            return res.status(401).json(
                createErrorResponse(401, ErrorCodes.INCORRECT_PASSWORD)
            );
        }
        
        if (!user.active) {
            logError('Login', ErrorCodes.ACCOUNT_INACTIVE, { username });
            return res.status(403).json(
                createErrorResponse(403, ErrorCodes.ACCOUNT_INACTIVE)
            );
        }
        
        // Success
        res.json({ success: true, sessionId: '...' });
        
    } catch (error) {
        console.error('[mbkauthe] Login error:', error);
        return res.status(500).json(
            createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR)
        );
    }
});
```

## Support

For questions about error handling:
- [GitHub Issues](https://github.com/MIbnEKhalid/mbkauthe/issues)
- Email: support@mbktech.org
