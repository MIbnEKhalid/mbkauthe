import { validateConfiguration, findValue } from '../config/index.js';

describe('Config Resolution and Validation', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  describe('findValue helper', () => {
    it('finds exact matching key', () => {
      const obj = { APP_NAME: 'mbkauthe' };
      expect(findValue(obj, 'APP_NAME')).toBe('mbkauthe');
    });

    it('finds case-insensitive matching key', () => {
      const obj = { app_name: 'test-app', domain: 'example.com' };
      expect(findValue(obj, 'APP_NAME')).toBe('test-app');
      expect(findValue(obj, 'DOMAIN')).toBe('example.com');
    });

    it('finds stripped-underscore matching key', () => {
      const obj = { mainsecrettoken: 'my-secret', devicetrustdurationdays: 14 };
      expect(findValue(obj, 'MAIN_SECRET_TOKEN')).toBe('my-secret');
      expect(findValue(obj, 'DEVICE_TRUST_DURATION_DAYS')).toBe(14);
    });

    it('returns undefined if key is missing or source is null', () => {
      expect(findValue(null, 'APP_NAME')).toBeUndefined();
      expect(findValue(undefined, 'APP_NAME')).toBeUndefined();
      expect(findValue({}, 'APP_NAME')).toBeUndefined();
    });
  });

  describe('Configuration Precedence', () => {
    it('prefers flat process.env over mbkautheVar, mbkauthShared, and defaults', () => {
      process.env.mbkautheVar = JSON.stringify({
        APP_NAME: 'from-mbkautheVar',
        MAIN_SECRET_TOKEN: 'token-var',
        SESSION_SECRET_KEY: 'secret-var-32-chars-long-enough-ok',
        IS_DEPLOYED: 'false',
        MBKAUTH_TWO_FA_ENABLE: 'false',
        DOMAIN: 'localhost',
        DB_TYPE: 'sqlite',
        SQLITE_PATH: './test.sqlite',
        LOGIN_REDIRECT_URL: '/from-var'
      });
      process.env.mbkauthShared = JSON.stringify({
        APP_NAME: 'from-shared',
        LOGIN_REDIRECT_URL: '/from-shared'
      });
      process.env.APP_NAME = 'from-flat-env';
      process.env.LOGIN_REDIRECT_URL = '/from-flat-env';

      const config = validateConfiguration();
      expect(config.APP_NAME).toBe('from-flat-env');
      expect(config.LOGIN_REDIRECT_URL).toBe('/from-flat-env');
    });

    it('prefers mbkautheVar over mbkauthShared and defaults', () => {
      delete process.env.APP_NAME;
      delete process.env.LOGIN_REDIRECT_URL;

      process.env.mbkautheVar = JSON.stringify({
        APP_NAME: 'from-mbkautheVar',
        MAIN_SECRET_TOKEN: 'token-var',
        SESSION_SECRET_KEY: 'secret-var-32-chars-long-enough-ok',
        IS_DEPLOYED: 'false',
        MBKAUTH_TWO_FA_ENABLE: 'false',
        DOMAIN: 'localhost',
        DB_TYPE: 'sqlite',
        SQLITE_PATH: './test.sqlite',
        LOGIN_REDIRECT_URL: '/from-var'
      });
      process.env.mbkauthShared = JSON.stringify({
        APP_NAME: 'from-shared',
        LOGIN_REDIRECT_URL: '/from-shared'
      });

      const config = validateConfiguration();
      expect(config.APP_NAME).toBe('from-mbkauthevar');
      expect(config.LOGIN_REDIRECT_URL).toBe('/from-var');
    });

    it('falls back to mbkauthShared when key not in process.env or mbkautheVar', () => {
      delete process.env.CLI_AUTH_BASE_URL;

      process.env.mbkautheVar = JSON.stringify({
        APP_NAME: 'testapp',
        MAIN_SECRET_TOKEN: 'token-var',
        SESSION_SECRET_KEY: 'secret-var-32-chars-long-enough-ok',
        IS_DEPLOYED: 'false',
        MBKAUTH_TWO_FA_ENABLE: 'false',
        DOMAIN: 'localhost',
        DB_TYPE: 'sqlite',
        SQLITE_PATH: './test.sqlite'
      });
      process.env.mbkauthShared = JSON.stringify({
        CLI_AUTH_BASE_URL: 'https://shared-auth.example.com'
      });

      const config = validateConfiguration();
      expect(config.CLI_AUTH_BASE_URL).toBe('https://shared-auth.example.com');
    });

    it('uses DEFAULT_CONFIG when key not provided anywhere', () => {
      process.env.mbkautheVar = JSON.stringify({
        APP_NAME: 'testapp',
        MAIN_SECRET_TOKEN: 'token-var',
        SESSION_SECRET_KEY: 'secret-var-32-chars-long-enough-ok',
        IS_DEPLOYED: 'false',
        MBKAUTH_TWO_FA_ENABLE: 'false',
        DOMAIN: 'localhost',
        DB_TYPE: 'sqlite',
        SQLITE_PATH: './test.sqlite'
      });
      delete process.env.mbkauthShared;

      const config = validateConfiguration();
      expect(config.DEVICE_TRUST_DURATION_DAYS).toBe(7);
      expect(config.COOKIE_EXPIRE_TIME).toBe(2);
      expect(config.LOGIN_REDIRECT_URL).toBe('/dashboard');
      expect(config.DB_TYPE).toBe('sqlite');
    });
  });

  describe('Flat Environment Variables without mbkautheVar', () => {
    it('successfully validates when all required keys are set as flat environment variables', () => {
      delete process.env.mbkautheVar;
      delete process.env.mbkauthShared;

      process.env.APP_NAME = 'flat-app';
      process.env.MAIN_SECRET_TOKEN = 'flat-token-secret-123';
      process.env.SESSION_SECRET_KEY = 'flat-session-secret-key-32-chars-ok';
      process.env.IS_DEPLOYED = 'false';
      process.env.MBKAUTH_TWO_FA_ENABLE = 'false';
      process.env.DOMAIN = 'localhost';
      process.env.DB_TYPE = 'sqlite';
      process.env.SQLITE_PATH = './data/test.sqlite';

      const config = validateConfiguration();
      expect(config.APP_NAME).toBe('flat-app');
      expect(config.MAIN_SECRET_TOKEN).toBe('flat-token-secret-123');
      expect(config.DB_TYPE).toBe('sqlite');
      expect(config.SQLITE_PATH).toBe('./data/test.sqlite');
    });

    it('supports lowercase and snake_case flat environment variables', () => {
      delete process.env.mbkautheVar;
      delete process.env.mbkauthShared;

      process.env.app_name = 'lowercase-app';
      process.env.main_secret_token = 'lowercase-token';
      process.env.session_secret_key = 'lowercase-session-secret-32-chars-ok';
      process.env.is_deployed = 'false';
      process.env.mbkauth_two_fa_enable = 'false';
      process.env.domain = 'localhost';
      process.env.db_type = 'sqlite';
      process.env.sqlite_path = './data/test.sqlite';

      const config = validateConfiguration();
      expect(config.APP_NAME).toBe('lowercase-app');
      expect(config.MAIN_SECRET_TOKEN).toBe('lowercase-token');
      expect(config.DOMAIN).toBe('localhost');
      expect(config.DB_TYPE).toBe('sqlite');
    });
  });

  describe('Configuration Validation Errors', () => {
    it('throws error when a required key is missing', () => {
      delete process.env.mbkautheVar;
      delete process.env.mbkauthShared;
      delete process.env.APP_NAME;
      delete process.env.MAIN_SECRET_TOKEN;
      delete process.env.SESSION_SECRET_KEY;
      delete process.env.IS_DEPLOYED;
      delete process.env.MBKAUTH_TWO_FA_ENABLE;
      delete process.env.DOMAIN;
      delete process.env.LOGIN_DB;
      delete process.env.SQLITE_PATH;

      expect(() => validateConfiguration()).toThrow(/Configuration Validation Failed/);
    });

    it('rejects invalid DOMAIN with protocol or port', () => {
      process.env.mbkautheVar = JSON.stringify({
        APP_NAME: 'testapp',
        MAIN_SECRET_TOKEN: 'token-var',
        SESSION_SECRET_KEY: 'secret-var-32-chars-long-enough-ok',
        IS_DEPLOYED: 'false',
        MBKAUTH_TWO_FA_ENABLE: 'false',
        DOMAIN: 'https://invalid-domain.com:8080',
        DB_TYPE: 'sqlite',
        SQLITE_PATH: './test.sqlite'
      });

      expect(() => validateConfiguration()).toThrow(/DOMAIN must be a hostname only/);
    });

    it('rejects invalid LOGIN_REDIRECT_URL', () => {
      process.env.mbkautheVar = JSON.stringify({
        APP_NAME: 'testapp',
        MAIN_SECRET_TOKEN: 'token-var',
        SESSION_SECRET_KEY: 'secret-var-32-chars-long-enough-ok',
        IS_DEPLOYED: 'false',
        MBKAUTH_TWO_FA_ENABLE: 'false',
        DOMAIN: 'localhost',
        DB_TYPE: 'sqlite',
        SQLITE_PATH: './test.sqlite',
        LOGIN_REDIRECT_URL: 'http://malicious-redirect.com'
      });

      expect(() => validateConfiguration()).toThrow(/LOGIN_REDIRECT_URL must be a relative path/);
    });
  });

  describe('3-Tier Source Precedence and Lowercase Normalization', () => {
    it('allows access via lowercase, uppercase, and camelCase properties', () => {
      process.env.app_name = 'mycoolapp';
      process.env.main_secret_token = 'secret-tok-123';
      process.env.session_secret_key = 'session-key-32-chars-long-valid!';
      process.env.is_deployed = 'false';
      process.env.mbkauth_two_fa_enable = 'false';
      process.env.domain = 'example.com';
      process.env.db_type = 'sqlite';
      process.env.sqlite_path = './test.sqlite';

      const config = validateConfiguration();
      // Lowercase
      expect(config.app_name).toBe('mycoolapp');
      expect(config.main_secret_token).toBe('secret-tok-123');
      expect(config.domain).toBe('example.com');
      expect(config.login_redirect_url).toBe('/dashboard');
      // Uppercase
      expect(config.APP_NAME).toBe('mycoolapp');
      expect(config.MAIN_SECRET_TOKEN).toBe('secret-tok-123');
      expect(config.DOMAIN).toBe('example.com');
      expect(config.LOGIN_REDIRECT_URL).toBe('/dashboard');
      // CamelCase via proxy
      expect(config.appName).toBe('mycoolapp');
      expect(config.mainSecretToken).toBe('secret-tok-123');
      expect(config.loginRedirectUrl).toBe('/dashboard');
    });

    it('VarName overrides mbkautheVar.VarName and mbkauthShared.VarName', () => {
      process.env.mbkauthShared = JSON.stringify({
        APP_NAME: 'from-shared',
        LOGIN_REDIRECT_URL: '/shared-redirect'
      });
      process.env.mbkautheVar = JSON.stringify({
        APP_NAME: 'from-var',
        LOGIN_REDIRECT_URL: '/var-redirect',
        MAIN_SECRET_TOKEN: 'token-from-var',
        SESSION_SECRET_KEY: 'session-secret-32-chars-ok-valid',
        IS_DEPLOYED: 'false',
        MBKAUTH_TWO_FA_ENABLE: 'false',
        DOMAIN: 'localhost',
        DB_TYPE: 'sqlite',
        SQLITE_PATH: './test.sqlite'
      });

      // Override only APP_NAME with simple VarName
      process.env.APP_NAME = 'from-simple-varname';

      const config = validateConfiguration();
      // Simple VarName overrides both mbkautheVar and mbkauthShared
      expect(config.app_name).toBe('from-simple-varname');
      expect(config.APP_NAME).toBe('from-simple-varname');
      // mbkautheVar overrides mbkauthShared
      expect(config.login_redirect_url).toBe('/var-redirect');
      expect(config.LOGIN_REDIRECT_URL).toBe('/var-redirect');
    });

    it('supports mbkautheVar.VarName and mbkauthShared.VarName as flat env variables', () => {
      delete process.env.mbkautheVar;
      delete process.env.mbkauthShared;

      // Set via mbkauthShared.VarName
      process.env['mbkauthShared.DOMAIN'] = 'shared-domain.org';
      process.env['mbkauthShared.LOGIN_REDIRECT_URL'] = '/shared-path';

      // Set via mbkautheVar.VarName (should override mbkauthShared.VarName)
      process.env['mbkautheVar.LOGIN_REDIRECT_URL'] = '/var-path';
      process.env['mbkautheVar.APP_NAME'] = 'var-app';
      process.env['mbkautheVar.MAIN_SECRET_TOKEN'] = 'token-123';
      process.env['mbkautheVar.SESSION_SECRET_KEY'] = 'sess-secret-32-chars-minimum-ok';
      process.env['mbkautheVar.IS_DEPLOYED'] = 'false';
      process.env['mbkautheVar.MBKAUTH_TWO_FA_ENABLE'] = 'false';
      process.env['mbkautheVar.DB_TYPE'] = 'sqlite';
      process.env['mbkautheVar.SQLITE_PATH'] = './test.sqlite';

      const config = validateConfiguration();
      expect(config.app_name).toBe('var-app');
      expect(config.domain).toBe('shared-domain.org');
      expect(config.login_redirect_url).toBe('/var-path');

      // Now simple VarName overrides both
      process.env.LOGIN_REDIRECT_URL = '/simple-wins';
      const updatedConfig = validateConfiguration();
      expect(updatedConfig.login_redirect_url).toBe('/simple-wins');
    });

    it('accepts PascalCase, camelCase, UPPERCASE, and lowercase seamlessly in all sources', () => {
      delete process.env.mbkautheVar;
      delete process.env.mbkauthShared;

      process.env['AppName'] = 'pascal-app';
      process.env['mainSecretToken'] = 'camel-secret';
      process.env['SESSION_SECRET_KEY'] = 'upper-session-32-chars-long-ok';
      process.env['is_deployed'] = 'false';
      process.env['Mbkauth_Two_Fa_Enable'] = 'false';
      process.env['Domain'] = 'localhost';
      process.env['dbType'] = 'sqlite';
      process.env['sqlitePath'] = './test.sqlite';

      const config = validateConfiguration();
      expect(config.app_name).toBe('pascal-app');
      expect(config.main_secret_token).toBe('camel-secret');
      expect(config.session_secret_key).toBe('upper-session-32-chars-long-ok');
      expect(config.is_deployed).toBe('false');
      expect(config.mbkauth_two_fa_enable).toBe('false');
      expect(config.domain).toBe('localhost');
      expect(config.db_type).toBe('sqlite');
      expect(config.sqlite_path).toBe('./test.sqlite');
    });
  });
});
