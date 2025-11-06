/**
 * Tests for SecurityAuditMiddleware
 */

import { SecurityAuditMiddleware } from './securityAuditMiddleware';
import { Context } from '../core';
import { Container } from 'typedi';

// Mock console methods for logger
const mockConsoleLog = jest.spyOn(console, 'log').mockImplementation();
const mockConsoleWarn = jest.spyOn(console, 'warn').mockImplementation();

describe('SecurityAuditMiddleware', () => {
  const createMockContext = (): Context => ({
    req: {
      method: 'GET',
      url: '/api/test',
      path: '/api/test',
      query: {},
      params: {},
      headers: { 'user-agent': 'test-agent' },
      ip: '192.168.1.1',
      body: undefined,
      userAgent: 'test-agent',
    },
    res: {
      status: jest.fn().mockReturnThis() as unknown as Context['res']['status'],
      json: jest.fn().mockReturnThis() as unknown as Context['res']['json'],
      send: jest.fn().mockReturnThis() as unknown as Context['res']['send'],
      header: jest.fn().mockReturnThis() as unknown as Context['res']['header'],
      headers: jest
        .fn()
        .mockReturnThis() as unknown as Context['res']['headers'],
      end: jest.fn().mockReturnThis() as unknown as Context['res']['end'],
      headersSent: false,
      statusCode: 200,
    },
    container: Container.of(),
    requestId: 'test-request-id',
    businessData: new Map(),
    user: undefined,
    responseData: undefined,
    startTime: Date.now(),
  });

  let mockContext: Context;

  beforeEach(() => {
    mockContext = createMockContext();
    jest.clearAllMocks();
  });

  describe('constructor', () => {
    it('should use default options when none provided', () => {
      const middleware = new SecurityAuditMiddleware();
      expect(middleware).toBeDefined();
    });

    it('should merge custom options with defaults', () => {
      const options = {
        logRequests: true,
        logResponses: true,
        logBodies: true,
        maxBodyLogSize: 2048,
        excludeHeaders: ['custom-header'],
        enableAnomalyDetection: false,
      };

      const middleware = new SecurityAuditMiddleware(options);
      expect(middleware).toBeDefined();
    });
  });

  describe('request logging', () => {
    it('should log incoming requests when enabled', async () => {
      const middleware = new SecurityAuditMiddleware({
        logRequests: true,
      });

      await middleware.before(mockContext);

      expect(mockConsoleLog).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Incoming request',
          method: 'GET',
          url: '/api/test',
          clientIP: '192.168.1.1',
          userAgent: 'test-agent',
        })
      );
    });

    it('should not log requests when disabled', async () => {
      const middleware = new SecurityAuditMiddleware({
        logRequests: false,
      });

      await middleware.before(mockContext);

      expect(mockConsoleLog).not.toHaveBeenCalled();
    });

    it('should log request bodies when enabled', async () => {
      const middleware = new SecurityAuditMiddleware({
        logRequests: true,
        logBodies: true,
      });

      const contextWithBody = {
        ...mockContext,
        req: {
          ...mockContext.req,
          body: { username: 'testuser', password: 'secret' },
        },
      };

      await middleware.before(contextWithBody);

      expect(mockConsoleLog).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Incoming request',
          body: expect.any(String),
        })
      );
    });

    it('should sanitize headers for logging', async () => {
      const middleware = new SecurityAuditMiddleware({
        logRequests: true,
      });

      const contextWithHeaders = {
        ...mockContext,
        req: {
          ...mockContext.req,
          headers: {
            authorization: 'Bearer secret-token',
            'x-api-key': 'secret-key',
            'content-type': 'application/json',
            'user-agent': 'test-agent',
          },
        },
      };

      await middleware.before(contextWithHeaders);

      expect(mockConsoleLog).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Incoming request',
          headers: expect.objectContaining({
            authorization: '[REDACTED]',
            'x-api-key': '[REDACTED]',
            'content-type': 'application/json',
          }),
        })
      );
    });
  });

  describe('response logging', () => {
    it('should log outgoing responses when enabled', async () => {
      const middleware = new SecurityAuditMiddleware({
        logResponses: true,
      });

      await middleware.before(mockContext);
      await middleware.after(mockContext);

      expect(mockConsoleLog).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Outgoing response',
          statusCode: 200,
          duration: expect.any(String),
          clientIP: '192.168.1.1',
        })
      );
    });

    it('should log response bodies when enabled', async () => {
      const middleware = new SecurityAuditMiddleware({
        logResponses: true,
        logBodies: true,
      });

      const contextWithResponse = {
        ...mockContext,
        responseData: { success: true, data: 'test' },
      };

      await middleware.before(contextWithResponse);
      await middleware.after(contextWithResponse);

      expect(mockConsoleLog).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Outgoing response',
          responseBody: expect.any(String),
        })
      );
    });
  });

  describe('suspicious pattern detection', () => {
    it('should detect SQL injection in URL', async () => {
      const middleware = new SecurityAuditMiddleware({
        enableAnomalyDetection: true,
      });

      const maliciousContext = {
        ...mockContext,
        req: {
          ...mockContext.req,
          url: '/api/users?id=1 OR 1=1; DROP TABLE users--',
          path: '/api/users',
        },
      };

      await middleware.before(maliciousContext);

      expect(mockConsoleWarn).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Security event detected',
          type: 'INJECTION_ATTEMPT',
          severity: 'HIGH',
          details: expect.objectContaining({
            suspiciousPatterns: expect.arrayContaining([
              expect.objectContaining({ type: 'sqlInjection' }),
            ]),
            location: 'url',
          }),
        })
      );
    });

    it('should detect XSS in request body', async () => {
      const middleware = new SecurityAuditMiddleware({
        enableAnomalyDetection: true,
      });

      const maliciousContext = {
        ...mockContext,
        req: {
          ...mockContext.req,
          body: '<script>alert("XSS")</script>',
        },
      };

      await middleware.before(maliciousContext);

      expect(mockConsoleWarn).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Security event detected',
          type: 'INJECTION_ATTEMPT',
          severity: 'HIGH',
          details: expect.objectContaining({
            suspiciousPatterns: expect.arrayContaining([
              expect.objectContaining({ type: 'xss' }),
            ]),
            location: 'body',
          }),
        })
      );
    });
  });

  describe('edge cases', () => {
    it('should handle missing headers gracefully', async () => {
      const middleware = new SecurityAuditMiddleware({
        logRequests: true,
      });

      const contextWithoutHeaders = {
        ...mockContext,
        req: {
          ...mockContext.req,
          headers: {},
        },
      };

      await expect(
        middleware.before(contextWithoutHeaders)
      ).resolves.not.toThrow();
    });
  });
});
