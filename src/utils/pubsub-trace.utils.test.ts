import {
  isPubSubMessage,
  extractTraceContext,
  injectTraceContext,
  createParentContext,
  PubSubMessage,
  TraceContext,
} from './pubsub-trace.utils';
import { Context } from '../core';

describe('pubsub-trace.utils', () => {
  describe('isPubSubMessage', () => {
    it('should return true for valid Pub/Sub message', () => {
      const message: PubSubMessage = {
        message: {
          data: 'dGVzdA==',
          messageId: '123',
          attributes: {},
        },
      };

      expect(isPubSubMessage(message)).toBe(true);
    });

    it('should return false for null', () => {
      expect(isPubSubMessage(null)).toBe(false);
    });

    it('should return false for undefined', () => {
      expect(isPubSubMessage(undefined)).toBe(false);
    });

    it('should return false for non-object', () => {
      expect(isPubSubMessage('string')).toBe(false);
      expect(isPubSubMessage(123)).toBe(false);
      expect(isPubSubMessage(true)).toBe(false);
    });

    it('should return false for object without message property', () => {
      expect(isPubSubMessage({ data: 'test' })).toBe(false);
    });

    it('should return false for message without data property', () => {
      expect(isPubSubMessage({ message: { messageId: '123' } })).toBe(false);
    });

    it('should return true for Pub/Sub message without optional fields', () => {
      const message = {
        message: {
          data: 'dGVzdA==',
        },
      };

      expect(isPubSubMessage(message)).toBe(true);
    });
  });

  describe('extractTraceContext', () => {
    it('should extract traceparent from message attributes', () => {
      const message: PubSubMessage = {
        message: {
          data: 'dGVzdA==',
          attributes: {
            traceparent:
              '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
          },
        },
      };

      const context = extractTraceContext(message);

      expect(context.traceparent).toBe(
        '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01'
      );
      expect(context.tracestate).toBeUndefined();
    });

    it('should extract both traceparent and tracestate', () => {
      const message: PubSubMessage = {
        message: {
          data: 'dGVzdA==',
          attributes: {
            traceparent:
              '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
            tracestate: 'vendor1=value1,vendor2=value2',
          },
        },
      };

      const context = extractTraceContext(message);

      expect(context.traceparent).toBe(
        '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01'
      );
      expect(context.tracestate).toBe('vendor1=value1,vendor2=value2');
    });

    it('should return empty context when attributes are missing', () => {
      const message: PubSubMessage = {
        message: {
          data: 'dGVzdA==',
        },
      };

      const context = extractTraceContext(message);

      expect(context.traceparent).toBeUndefined();
      expect(context.tracestate).toBeUndefined();
    });

    it('should return empty context when trace headers are missing', () => {
      const message: PubSubMessage = {
        message: {
          data: 'dGVzdA==',
          attributes: {
            eventType: 'user.created',
          },
        },
      };

      const context = extractTraceContext(message);

      expect(context.traceparent).toBeUndefined();
      expect(context.tracestate).toBeUndefined();
    });
  });

  describe('injectTraceContext', () => {
    it('should return message with attributes when OpenTelemetry not available', () => {
      const message = {
        data: 'dGVzdA==',
        attributes: {
          eventType: 'user.created',
        },
      };

      const result = injectTraceContext(message);

      // Since OpenTelemetry is not available in test env without active span,
      // it should return message without trace context
      expect(result.data).toBe('dGVzdA==');
      expect(result.attributes.eventType).toBe('user.created');
    });

    it('should preserve existing attributes when trace injection fails', () => {
      const message = {
        data: 'dGVzdA==',
        attributes: {
          eventType: 'user.created',
          userId: '123',
        },
      };

      const result = injectTraceContext(message);

      expect(result.data).toBe('dGVzdA==');
      expect(result.attributes.eventType).toBe('user.created');
      expect(result.attributes.userId).toBe('123');
    });

    it('should initialize attributes when not provided', () => {
      const message = {
        data: 'dGVzdA==',
      };

      const result = injectTraceContext(message);

      expect(result.data).toBe('dGVzdA==');
      expect(result.attributes).toBeDefined();
    });

    it('should return message without trace context when no active span', () => {
      const message = {
        data: 'dGVzdA==',
        attributes: {
          eventType: 'user.created',
        },
      };

      const result = injectTraceContext(message);

      expect(result.data).toBe('dGVzdA==');
      expect(result.attributes.eventType).toBe('user.created');
    });

    it('should work with Noony context parameter', () => {
      const message = {
        data: 'dGVzdA==',
        attributes: {
          eventType: 'user.created',
        },
      };

      const context = {
        req: {},
        res: {},
        businessData: new Map(),
      } as Context;

      const result = injectTraceContext(message, context);

      expect(result.data).toBe('dGVzdA==');
      expect(result.attributes.eventType).toBe('user.created');
    });
  });

  describe('createParentContext', () => {
    it('should create carrier with traceparent', () => {
      const traceContext: TraceContext = {
        traceparent: '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
      };

      const carrier = createParentContext(traceContext);

      expect(carrier.traceparent).toBe(
        '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01'
      );
      expect(carrier.tracestate).toBeUndefined();
    });

    it('should create carrier with both traceparent and tracestate', () => {
      const traceContext: TraceContext = {
        traceparent: '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
        tracestate: 'vendor1=value1,vendor2=value2',
      };

      const carrier = createParentContext(traceContext);

      expect(carrier.traceparent).toBe(
        '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01'
      );
      expect(carrier.tracestate).toBe('vendor1=value1,vendor2=value2');
    });

    it('should return empty carrier when traceparent is missing', () => {
      const traceContext: TraceContext = {
        tracestate: 'vendor1=value1',
      };

      const carrier = createParentContext(traceContext);

      expect(carrier).toEqual({});
    });

    it('should return empty carrier for empty trace context', () => {
      const traceContext: TraceContext = {};

      const carrier = createParentContext(traceContext);

      expect(carrier).toEqual({});
    });
  });
});
