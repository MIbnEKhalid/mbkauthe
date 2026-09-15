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

export interface AuthEventMap {
  "auth:login:success": AuthLoginSuccessEvent;
  "auth:login:failed": AuthLoginFailedEvent;
  "auth:logout": AuthLogoutEvent;
  "auth:token:created": AuthTokenCreatedEvent;
  "auth:token:revoked": AuthTokenRevokedEvent;
  "auth:account:switched": AuthAccountSwitchedEvent;
  "auth:cli:approved": AuthCliApprovedEvent;
  "auth:cli:denied": AuthCliDeniedEvent;
}

export type AuthEventName = keyof AuthEventMap;
export type AuthEventListener<K extends AuthEventName> = (payload: AuthEventMap[K]) => void | Promise<void>;
