/**
 * Basic test for ExpressionPermissionResolver
 */

import { ExpressionPermissionResolver } from './ExpressionPermissionResolver';
import { CacheAdapter } from '../cache/CacheAdapter';

describe('ExpressionPermissionResolver', () => {
  it('should be defined', () => {
    const mockCache: CacheAdapter = {
      get: jest.fn(),
      set: jest.fn(),
      delete: jest.fn(),
      deletePattern: jest.fn(),
      flush: jest.fn(),
      getStats: jest.fn(),
      getName: jest.fn().mockReturnValue('test-cache'),
    };
    const resolver = new ExpressionPermissionResolver(mockCache);
    expect(resolver).toBeDefined();
  });
});
