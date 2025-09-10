/**
 * Basic test for RateLimitingMiddleware
 */

import { RateLimitingMiddleware } from './rateLimitingMiddleware';

describe('RateLimitingMiddleware', () => {
  it('should be defined', () => {
    const middleware = new RateLimitingMiddleware();
    expect(middleware).toBeDefined();
  });
});
