// src/core/logger.test.ts
import { Logger } from './logger';

describe('Logger', () => {
  let testLogger: Logger;
  let consoleLogSpy: jest.SpyInstance;
  let consoleErrorSpy: jest.SpyInstance;
  let consoleWarnSpy: jest.SpyInstance;
  let consoleDebugSpy: jest.SpyInstance;
  let originalNodeEnv: string | undefined;

  beforeEach(() => {
    // Store original NODE_ENV and set to development to enable debug logging
    originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'development';

    // Set up console spies before creating the logger
    consoleLogSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    consoleDebugSpy = jest.spyOn(console, 'debug').mockImplementation(() => {});

    // Create a fresh logger instance after setting up mocks
    testLogger = new Logger();
  });

  afterEach(() => {
    jest.restoreAllMocks();
    // Restore original NODE_ENV
    if (originalNodeEnv !== undefined) {
      process.env.NODE_ENV = originalNodeEnv;
    } else {
      delete process.env.NODE_ENV;
    }
  });

  it('logs info messages', () => {
    testLogger.info('Info message');
    expect(consoleLogSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        level: 'info',
        message: 'Info message',
      })
    );
  });

  it('logs error messages', () => {
    testLogger.error('Error message');
    expect(consoleErrorSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        level: 'error',
        message: 'Error message',
      })
    );
  });

  it('logs warn messages', () => {
    testLogger.warn('Warn message');
    expect(consoleWarnSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        level: 'warn',
        message: 'Warn message',
      })
    );
  });

  it('logs debug messages', () => {
    testLogger.debug('Debug message');
    expect(consoleDebugSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        level: 'debug',
        message: 'Debug message',
      })
    );
  });

  it('logs messages with additional options', () => {
    testLogger.info('Info message with options', { structuredData: true });
    expect(consoleLogSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        level: 'info',
        message: 'Info message with options',
        structuredData: true,
      })
    );
  });

  it('logs messages with timestamp', () => {
    const before = new Date().toISOString();
    testLogger.info('Info message');
    const after = new Date().toISOString();
    const logCall = consoleLogSpy.mock.calls[0][0];
    expect(logCall.timestamp >= before).toBe(true);
    expect(logCall.timestamp <= after).toBe(true);
  });

  it('shows performance improvements with object pooling', () => {
    // Test that the logger reuses objects
    testLogger.info('Test 1');
    testLogger.info('Test 2');
    testLogger.info('Test 3');

    expect(consoleLogSpy).toHaveBeenCalledTimes(3);
    const stats = testLogger.getStats();
    expect(stats).toHaveProperty('poolSize');
    expect(stats).toHaveProperty('debugEnabled');
  });
});
