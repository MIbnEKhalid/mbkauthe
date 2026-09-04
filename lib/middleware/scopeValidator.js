import { canAccessMethod } from "#config.js";
import { ErrorCodes, createErrorResponse } from '../utils/errors.js';

export function validateTokenScope(req, res, next) {
  const tokenScope = req.auth?.type === 'api-token'
    ? req.auth.tokenScope
    : req.session?.user?.sessionId === 'api-token-session'
      ? req.session.user.tokenScope
      : null;

  if (tokenScope && !canAccessMethod(tokenScope, req.method)) {
    return res.status(403).json(createErrorResponse(403, ErrorCodes.TOKEN_SCOPE_INSUFFICIENT, {
      message: `Token scope '${tokenScope}' does not allow ${req.method} requests`,
      tokenScope,
      requestedMethod: req.method,
      hint: 'Use a token with write scope for write operations'
    }));
  }

  next();
}