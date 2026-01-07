/**
 * Scope Validation Middleware
 * Validates HTTP methods against token scopes
 */

import { canAccessMethod } from '../config/tokenScopes.js';
import { ErrorCodes, createErrorResponse } from '../utils/errors.js';

/**
 * Middleware to validate that the token's scope allows the request method
 * Only applies to API token authentication (not session cookies)
 */
export function validateTokenScope(req, res, next) {
  // Only validate for API token requests (not cookie-based sessions)
  // Check if this request was authenticated via API token
  if (req.session?.user?.sessionId === 'api-token-session' && req.session?.user?.tokenScope) {
    const tokenScope = req.session.user.tokenScope;
    const requestMethod = req.method;
    
    // Check if scope allows this HTTP method
    if (!canAccessMethod(tokenScope, requestMethod)) {
      return res.status(403).json(createErrorResponse(403, ErrorCodes.TOKEN_SCOPE_INSUFFICIENT, {
        message: `Token scope '${tokenScope}' does not allow ${requestMethod} requests`,
        tokenScope,
        requestedMethod: requestMethod,
        hint: 'Use a token with write scope for write operations'
      }));
    }
  }
  
  next();
}
