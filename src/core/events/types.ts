/**
 * Domain Auth Event Types
 */

export interface AuthLoginSuccessEvent {
  userId: number | string;
  username: string;
  ip?: string;
  userAgent?: string;
  appKey?: string;
  authMethod?: "password" | "oauth" | "cli" | "token" | "session" | "2fa";
  provider?: string;
  timestamp: Date;
}

export interface AuthLoginFailedEvent {
  username?: string;
  reason: string;
  ip?: string;
  userAgent?: string;
  appKey?: string;
  provider?: string;
  timestamp: Date;
}

export interface AuthLogoutEvent {
  userId?: number | string;
  sessionId?: string;
  allDevices?: boolean;
  timestamp: Date;
}

export interface AuthTokenCreatedEvent {
  tokenId: number | string;
  userId: number | string;
  name: string;
  scopes: string[];
  expiresAt?: Date | null;
  timestamp: Date;
}

export interface AuthTokenRevokedEvent {
  tokenId: number | string;
  userId: number | string;
  timestamp: Date;
}

export interface AuthAccountSwitchedEvent {
  fromUserId?: number | string;
  toUserId: number | string;
  username: string;
  timestamp: Date;
}

export interface AuthCliApprovedEvent {
  deviceCode: string;
  userCode: string;
  userId: number | string;
  timestamp: Date;
}

export interface AuthCliDeniedEvent {
  deviceCode: string;
  userCode: string;
  timestamp: Date;
}

export interface OAuthBeginEvent {
  provider: string;
  action: "login" | "link";
  userId?: string | number;
  ip?: string;
  userAgent?: string;
  timestamp: Date;
}

export interface OAuthCallbackSuccessEvent {
  provider: string;
  providerUserId: string;
  userId: string | number;
  username: string;
  action: "login" | "link";
  ip?: string;
  userAgent?: string;
  timestamp: Date;
}

export interface OAuthCallbackFailureEvent {
  provider: string;
  reason: string;
  code?: string;
  ip?: string;
  userAgent?: string;
  timestamp: Date;
}

export interface OAuthAccountLinkedEvent {
  provider: string;
  providerUserId: string;
  userId: string | number;
  username?: string;
  timestamp: Date;
}

export interface OAuthAccountUnlinkedEvent {
  provider: string;
  userId: string | number;
  timestamp: Date;
}

export interface OAuthNewUserCreatedEvent {
  provider: string;
  providerUserId: string;
  userId: string | number;
  username: string;
  email?: string | null;
  timestamp: Date;
}

export interface OAuthSuspiciousEvent {
  provider?: string;
  reason: string;
  details?: Record<string, any>;
  ip?: string;
  userAgent?: string;
  timestamp: Date;
}

export interface AuthEventMap {
  "auth:login:success": AuthLoginSuccessEvent;
  "auth:login:failed": AuthLoginFailedEvent;
  "auth:logout": AuthLogoutEvent;
  "auth:token:created": AuthTokenCreatedEvent;
  "auth:token:revoked": AuthTokenRevokedEvent;
  "auth:account:switched": AuthAccountSwitchedEvent;
  "auth:cli:approved": AuthCliApprovedEvent;
  "auth:cli:denied": AuthCliDeniedEvent;

  // OAuth events (dot & colon notation)
  "oauth.begin": OAuthBeginEvent;
  "oauth.callback.success": OAuthCallbackSuccessEvent;
  "oauth.callback.failure": OAuthCallbackFailureEvent;
  "oauth.account.linked": OAuthAccountLinkedEvent;
  "oauth.account.unlinked": OAuthAccountUnlinkedEvent;
  "oauth.new_user.created": OAuthNewUserCreatedEvent;
  "oauth.suspicious": OAuthSuspiciousEvent;

  "oauth:begin": OAuthBeginEvent;
  "oauth:callback:success": OAuthCallbackSuccessEvent;
  "oauth:callback:failure": OAuthCallbackFailureEvent;
  "oauth:account:linked": OAuthAccountLinkedEvent;
  "oauth:account:unlinked": OAuthAccountUnlinkedEvent;
  "oauth:new_user:created": OAuthNewUserCreatedEvent;
  "oauth:suspicious": OAuthSuspiciousEvent;
}

export type AuthEventName = keyof AuthEventMap;
export type AuthEventListener<K extends AuthEventName> = (payload: AuthEventMap[K]) => void | Promise<void>;

