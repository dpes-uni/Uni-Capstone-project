const logger = require('../src/utils/logger');

describe('logger', () => {
  it('exports the standard logging methods', () => {
    for (const level of ['debug', 'info', 'warn', 'error']) {
      expect(typeof logger[level]).toBe('function');
    }
  });

  it('logs structured messages without throwing', () => {
    expect(() => logger.info('test message', { meta: 'value' })).not.toThrow();
    expect(() => logger.error(new Error('boom'), { context: 'test' })).not.toThrow();
    expect(() => logger.warn('warning', { detail: 1 })).not.toThrow();
  });
});