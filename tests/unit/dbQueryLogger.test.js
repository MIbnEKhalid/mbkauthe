import { describe, test, expect, beforeEach } from 'vitest';
import { isDbLogsEnabled, attachDevQueryLogger, getQueryCount, getQueryLog, resetQueryCount, resetQueryLog } from '../../src/db/dbQueryLogger.js';

describe('dbQueryLogger', () => {
  beforeEach(() => {
    resetQueryCount();
    resetQueryLog();
    delete process.env.dbLogs;
    delete process.env.DB_LOGS;
  });

  test('isDbLogsEnabled honors environment settings', () => {
    process.env.dbLogs = 'false';
    expect(isDbLogsEnabled()).toBe(false);

    process.env.dbLogs = 'true';
    expect(isDbLogsEnabled()).toBe(true);

    delete process.env.dbLogs;
    process.env.DB_LOGS = 'false';
    expect(isDbLogsEnabled()).toBe(false);

    process.env.DB_LOGS = 'true';
    expect(isDbLogsEnabled()).toBe(true);

    delete process.env.DB_LOGS;
    expect(isDbLogsEnabled()).toBe(false);
  });

  test('captures queries when pool is instrumented', async () => {
    process.env.dbLogs = 'true';

    const mockPool = {
      name: 'test-pool',
      totalCount: 5,
      idleCount: 3,
      waitingCount: 0,
      async query(sql, params) {
        return { command: 'SELECT', rowCount: 1, rows: [{ id: 1, name: 'Alice' }] };
      },
    };

    attachDevQueryLogger(mockPool);

    const result = await mockPool.query('SELECT * FROM users WHERE id = $1', [1]);
    expect(result.rows[0].name).toBe('Alice');

    expect(getQueryCount()).toBe(1);
    const logs = getQueryLog();
    expect(logs.length).toBe(1);
    expect(logs[0].query).toBe('SELECT * FROM users WHERE id = $1');
    expect(logs[0].values).toEqual([1]);
    expect(logs[0].success).toBe(true);
    expect(logs[0].pool.name).toBe('test-pool');
  });

  test('resetQueryCount and resetQueryLog clear all stored history', async () => {
    process.env.dbLogs = 'true';

    const mockPool = {
      name: 'test-reset-pool',
      async query() {
        return { command: 'SELECT', rowCount: 0, rows: [] };
      },
    };

    attachDevQueryLogger(mockPool);
    await mockPool.query('SELECT 1');
    expect(getQueryCount()).toBe(1);
    expect(getQueryLog().length).toBe(1);

    resetQueryCount();
    resetQueryLog();

    expect(getQueryCount()).toBe(0);
    expect(getQueryLog().length).toBe(0);
  });
});
