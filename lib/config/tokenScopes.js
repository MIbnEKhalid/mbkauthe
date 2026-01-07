/**
 * API Token Scope Configuration
 * Defines available scopes and methods for token-based access control
 */

// Available scopes
export const TOKEN_SCOPES = {
  'read-only': {
    name: 'Read Only',
    description: 'Allows only read operations (GET, HEAD, OPTIONS)',
    allowedMethods: ['GET', 'HEAD', 'OPTIONS']
  },
  'write': {
    name: 'Write (Full Access)',
    description: 'Allows all operations (GET, POST, PUT, DELETE, PATCH, etc.)',
    allowedMethods: '*' // All methods
  }
};

export const DEFAULT_SCOPE = 'read-only';

/**
 * Check if a token scope allows the given HTTP method
 * @param {string} scope - Token scope ('read-only' or 'write')
 * @param {string} method - HTTP method (GET, POST, etc.)
 * @returns {boolean}
 */
export function canAccessMethod(scope, method) {
  if (!scope || !TOKEN_SCOPES[scope]) return false;
  
  const scopeConfig = TOKEN_SCOPES[scope];
  
  // Full access scope
  if (scopeConfig.allowedMethods === '*') return true;
  
  // Check if method is in allowed list
  return scopeConfig.allowedMethods.includes(method.toUpperCase());
}

/**
 * Validate if a scope is valid
 * @param {string} scope - Scope to validate
 * @returns {boolean}
 */
export function isValidScope(scope) {
  return TOKEN_SCOPES.hasOwnProperty(scope);
}

/**
 * Get all available scopes with descriptions
 * @returns {Object}
 */
export function getAvailableScopes() {
  return Object.entries(TOKEN_SCOPES).map(([key, value]) => ({
    scope: key,
    name: value.name,
    description: value.description
  }));
}
