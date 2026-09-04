export const TOKEN_SCOPES = {
  'read-only': {
    name: 'Read Only',
    description: 'Allows only read operations (GET, HEAD, OPTIONS)',
    allowedMethods: ['GET', 'HEAD', 'OPTIONS']
  },
  'write': {
    name: 'Write (Full Access)',
    description: 'Allows all operations (GET, POST, PUT, DELETE, PATCH, etc.)',
    allowedMethods: '*'
  }
};

export const DEFAULT_SCOPE = 'read-only';

export function canAccessMethod(scope, method) {
  const allowed = TOKEN_SCOPES[scope]?.allowedMethods;
  return Boolean(allowed && (allowed === '*' || allowed.includes(method.toUpperCase())));
}

export function isValidScope(scope) {
  return Object.hasOwn(TOKEN_SCOPES, scope);
}

export function getAvailableScopes() {
  return Object.entries(TOKEN_SCOPES).map(([key, value]) => ({
    scope: key,
    name: value.name,
    description: value.description
  }));
}