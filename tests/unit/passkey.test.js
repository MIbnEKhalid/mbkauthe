import { readFile } from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, test, expect, beforeAll, beforeEach } from 'vitest';
import { PasskeyService } from '../../src/services/PasskeyService.js';
import { PasskeyRepository } from '../../src/db/repositories/PasskeyRepository.js';
import { SqlitePool } from '../../src/db/adapters/SqliteAdapter.js';
import { sqliteDialect } from '../../src/db/dialects/SqliteDialect.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = path.join(__dirname, '../../docs/schema/db.sqlite.sql');

describe('Passkey Subsystem Unit Tests', () => {
  let schemaSql;
  let pool;
  let repo;
  let service;

  beforeAll(async () => {
    schemaSql = await readFile(SCHEMA_PATH, 'utf8');
  });

  beforeEach(async () => {
    pool = new SqlitePool(':memory:');
    pool.execScript(schemaSql);

    await pool.query(`INSERT INTO mbkcore_users (username, is_active, role, full_name) VALUES ('alice', 1, 'normaluser', 'Alice Smith');`);

    repo = new PasskeyRepository({ db: pool, dialect: sqliteDialect });
    service = new PasskeyService(null, repo, { rpName: 'MBKTech', rpID: 'localhost' });
  });

  test('PasskeyRepository: create, find, list, update counter, rename, delete', async () => {
    const pk = await repo.createPasskey({
      username: 'alice',
      credential_id: 'cred_1',
      public_key: 'pub_1',
      counter: 0,
      device_type: 'single_device',
      backed_up: false,
      transports: ['internal'],
      name: 'MacBook Touch ID',
    });

    expect(pk.id).toBeTruthy();
    expect(pk.username).toBe('alice');
    expect(pk.credential_id).toBe('cred_1');

    const found = await repo.findByCredentialId('cred_1');
    expect(found).not.toBeNull();
    expect(found.name).toBe('MacBook Touch ID');
    expect(found.user.username).toBe('alice');
    expect(found.user.full_name).toBe('Alice Smith');

    const count = await repo.countByUsername('alice');
    expect(count).toBe(1);

    const list = await repo.listByUsername('alice');
    expect(list.length).toBe(1);
    expect(list[0].credential_id).toBe('cred_1');

    await repo.updateCounterAndLastUsed('cred_1', 10);
    const updated = await repo.findByCredentialId('cred_1');
    expect(Number(updated.counter)).toBe(10);
    expect(updated.last_used_at).not.toBeNull();

    const renamed = await repo.renamePasskey(pk.id, 'alice', 'Office YubiKey');
    expect(renamed).toBe(true);
    const afterRename = await repo.findByCredentialId('cred_1');
    expect(afterRename.name).toBe('Office YubiKey');

    const deleted = await repo.deleteByIdAndUsername(pk.id, 'alice');
    expect(deleted).toBe(true);
    expect(await repo.findByCredentialId('cred_1')).toBeNull();
    expect(await repo.countByUsername('alice')).toBe(0);
  });

  test('PasskeyService: generates registration options with user and exclusions', async () => {
    // Register one key first
    await repo.createPasskey({
      username: 'alice',
      credential_id: 'existing_cred',
      public_key: 'pub_existing',
      name: 'Existing Key',
    });

    const regOptions = await service.generateRegistrationOptions('alice', 'Alice Smith');
    expect(regOptions.challenge).toBeTruthy();
    expect(regOptions.rp.name).toBe('MBKTech');
    expect(regOptions.rp.id).toBe('localhost');
    expect(regOptions.user.name).toBe('alice');
    expect(regOptions.user.displayName).toBe('Alice Smith');
    expect(regOptions.excludeCredentials?.length).toBe(1);
    expect(regOptions.excludeCredentials[0].id).toBe('existing_cred');
  });

  test('PasskeyService: generates authentication options with allowCredentials for target user', async () => {
    await repo.createPasskey({
      username: 'alice',
      credential_id: 'key_123',
      public_key: 'pub_123',
      name: 'Key 123',
    });

    const authOptionsTargeted = await service.generateAuthenticationOptions('alice');
    expect(authOptionsTargeted.challenge).toBeTruthy();
    expect(authOptionsTargeted.rpId).toBe('localhost');
    expect(authOptionsTargeted.allowCredentials?.length).toBe(1);
    expect(authOptionsTargeted.allowCredentials[0].id).toBe('key_123');

    // Discoverable / autofill credentials (no user specified)
    const authOptionsAutofill = await service.generateAuthenticationOptions();
    expect(authOptionsAutofill.challenge).toBeTruthy();
    expect(authOptionsAutofill.allowCredentials).toBeUndefined();
  });

  test('PasskeyService: list, rename and delete methods', async () => {
    const created = await repo.createPasskey({
      username: 'alice',
      credential_id: 'key_abc',
      public_key: 'pub_abc',
      name: 'Old Name',
    });

    const list = await service.listUserPasskeys('alice');
    expect(list.length).toBe(1);

    await service.renamePasskey(created.id, 'alice', 'Brand New Name');
    const updated = await repo.findByCredentialId('key_abc');
    expect(updated.name).toBe('Brand New Name');

    await service.deletePasskey(created.id, 'alice');
    expect((await service.listUserPasskeys('alice')).length).toBe(0);
  });
});
