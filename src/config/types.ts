export interface OAuthProviderConfig {
  login_enabled?: 'true' | 'false' | 'f' | boolean;
  loginEnabled?: 'true' | 'false' | 'f' | boolean;
  enabled?: 'true' | 'false' | 'f' | boolean;
  client_id?: string;
  clientId?: string;
  client_secret?: string;
  clientSecret?: string;
  tenant?: string;
  tenant_id?: string;
  tenantId?: string;
  team_id?: string;
  teamId?: string;
  key_id?: string;
  keyId?: string;
  private_key?: string;
  privateKey?: string;
  issuer?: string;
  type?: 'oauth2' | 'oidc' | string;
  scopes?: string[] | string;
  redirect_uri?: string;
  redirectUri?: string;
  [key: string]: any;
}

export type OAuthProvidersConfig = Record<string, OAuthProviderConfig>;

export interface MBKAuthConfig {
  // Lowercase normalized
  app_name?: string;
  session_secret_key?: string;
  main_secret_token?: string;
  is_deployed?: 'true' | 'false' | 'f' | boolean;
  domain?: string;
  db_type?: 'postgres' | 'sqlite' | string;
  login_db?: string;
  sqlite_path?: string;
  mbkauth_two_fa_enable?: 'true' | 'false' | 'f' | boolean;
  cookie_expire_time?: number;
  device_trust_duration_days?: number;
  login_redirect_url?: string;
  max_sessions_per_user?: number;
  cli_auth_base_url?: string;
  cli_auth_enabled?: 'true' | 'false' | 'f' | boolean;
  oauth_providers?: OAuthProvidersConfig;

  // Uppercase canonical
  APP_NAME: string;
  SESSION_SECRET_KEY: string;
  MAIN_SECRET_TOKEN: string;
  IS_DEPLOYED: 'true' | 'false' | 'f' | boolean;
  DOMAIN: string;
  DB_TYPE?: 'postgres' | 'sqlite' | string;
  LOGIN_DB?: string;
  SQLITE_PATH?: string;
  MBKAUTH_TWO_FA_ENABLE: 'true' | 'false' | 'f' | boolean;
  COOKIE_EXPIRE_TIME?: number;
  DEVICE_TRUST_DURATION_DAYS?: number;
  LOGIN_REDIRECT_URL?: string;
  MAX_SESSIONS_PER_USER?: number;
  CLI_AUTH_BASE_URL?: string;
  CLI_AUTH_ENABLED?: 'true' | 'false' | 'f' | boolean;
  OAUTH_PROVIDERS?: OAuthProvidersConfig;

  [key: string]: any;
}
