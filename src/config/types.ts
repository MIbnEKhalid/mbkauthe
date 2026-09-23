export interface OAuthProviderConfig {
  login_enabled?: 'true' | 'false' | 'f' | boolean;
  client_id?: string;
  client_secret?: string;
  tenant?: string;
  tenant_id?: string;
  team_id?: string;
  key_id?: string;
  private_key?: string;
  issuer?: string;
  type?: 'oauth2' | 'oidc' | string;
  scopes?: string[] | string;
  redirect_uri?: string;
  [key: string]: any;
}

export type OAuthProvidersConfig = Record<string, OAuthProviderConfig>;

export interface MBKAuthConfig {
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
  LOGIN_REDIRECT_URL?: string;
  MAX_SESSIONS_PER_USER?: number;
  CLI_AUTH_BASE_URL?: string;
  CLI_AUTH_ENABLED?: 'true' | 'false' | 'f' | boolean;
  OAUTH_PROVIDERS?: OAuthProvidersConfig;

  [key: string]: any;
}
