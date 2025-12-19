import { OpenTelemetryMiddleware } from './openTelemetryMiddleware';
import { Context } from '../core';
import { TelemetryProvider, GenericSpan } from '../core/telemetry/provider';
import { NoopProvider } from '../core/telemetry/providers';

// Mock the @opentelemetry/api module at the module level
let mockOtelApi: any = null;

jest.mock('@opentelemetry/api', () => {
  return mockOtelApi || jest.requireActual('@opentelemetry/api');
});

describe('OpenTelemetryMiddleware', () => {
  let context: Context;
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };

    // Reset mock
    mockOtelApi = null;

    context = {
      req: {
        method: 'GET',
        path: '/api/users',
        url: '/api/users?page=1',
        headers: {
          'user-agent': 'Mozilla/5.0',
        },
        body: null,
      },
      res: {
        statusCode: 200,
        header: jest.fn(),
      },
      requestId: 'req-123',
      startTime: Date.now(),
      businessData: new Map(),
    } as any;

    jest.spyOn(console, 'log').mockImplementation();
    jest.spyOn(console, 'error').mockImplementation();
    jest.spyOn(console, 'warn').mockImplementation();
  });

  afterEach(() => {
    process.env = originalEnv;
    jest.restoreAllMocks();
    mockOtelApi = null;
  });

  describe('provider auto-detection', () => {
    it('should use Noop provider when NODE_ENV=test', async () => {
      process.env.NODE_ENV = 'test';
      delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT;

      const middleware = new OpenTelemetryMiddleware();
      await middleware.before(context);

      // Noop provider doesn't create spans
      expect(context.businessData.get('otel_span')).toBeUndefined();
    });

    it('should use Console provider when NODE_ENV=development', async () => {
      process.env.NODE_ENV = 'development';
      delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT;

      const middleware = new OpenTelemetryMiddleware();
      await middleware.before(context);

      // Console provider logs initialization
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('[Telemetry] Console provider initialized')
      );
    });

    it('should use explicit provider when provided', async () => {
      const mockProvider: TelemetryProvider = {
        name: 'mock',
        validate: jest.fn().mockResolvedValue({ valid: true }),
        initialize: jest.fn().mockResolvedValue(undefined),
        createSpan: jest.fn().mockReturnValue(undefined),
        recordMetric: jest.fn(),
        log: jest.fn(),
        isReady: jest.fn().mockReturnValue(true),
        shutdown: jest.fn().mockResolvedValue(undefined),
      };

      const middleware = new OpenTelemetryMiddleware({
        provider: mockProvider,
        enabled: true,
      });
      await middleware.before(context);

      // Initialize is called during first before() call
      expect(mockProvider.initialize).toHaveBeenCalledWith(
        expect.objectContaining({
          serviceName: expect.any(String),
          serviceVersion: expect.any(String),
          environment: expect.any(String),
        })
      );
    });

    it('should not initialize when enabled=false', async () => {
      const middleware = new OpenTelemetryMiddleware({ enabled: false });
      await middleware.before(context);

      expect(context.businessData.get('otel_span')).toBeUndefined();
    });
  });

  describe('span creation', () => {
    it('should create span and store in businessData', async () => {
      const mockSpan: GenericSpan = {
        setAttributes: jest.fn(),
        recordException: jest.fn(),
        setStatus: jest.fn(),
        end: jest.fn(),
      };

      const mockProvider: TelemetryProvider = {
        name: 'mock',
        validate: jest.fn().mockResolvedValue({ valid: true }),
        initialize: jest.fn().mockResolvedValue(undefined),
        createSpan: jest.fn().mockReturnValue(mockSpan),
        recordMetric: jest.fn(),
        log: jest.fn(),
        isReady: jest.fn().mockReturnValue(true),
        shutdown: jest.fn().mockResolvedValue(undefined),
      };

      const middleware = new OpenTelemetryMiddleware({
        provider: mockProvider,
        enabled: true,
      });
      await middleware.before(context);

      expect(context.businessData.get('otel_span')).toBe(mockSpan);
      expect(mockProvider.createSpan).toHaveBeenCalledWith(context);
    });

    it('should not create span when shouldTrace returns false', async () => {
      const mockProvider: TelemetryProvider = {
        name: 'mock',
        validate: jest.fn().mockResolvedValue({ valid: true }),
        initialize: jest.fn().mockResolvedValue(undefined),
        createSpan: jest.fn(),
        recordMetric: jest.fn(),
        log: jest.fn(),
        isReady: jest.fn().mockReturnValue(true),
        shutdown: jest.fn().mockResolvedValue(undefined),
      };

      const middleware = new OpenTelemetryMiddleware({
        provider: mockProvider,
        shouldTrace: (ctx) => ctx.req.path !== '/health',
      });

      context.req.path = '/health';
      await middleware.before(context);

      expect(mockProvider.createSpan).not.toHaveBeenCalled();
    });

    it('should extract custom attributes when provided', async () => {
      const mockSpan: GenericSpan = {
        setAttributes: jest.fn(),
        recordException: jest.fn(),
        setStatus: jest.fn(),
        end: jest.fn(),
      };

      const mockProvider: TelemetryProvider = {
        name: 'mock',
        validate: jest.fn().mockResolvedValue({ valid: true }),
        initialize: jest.fn().mockResolvedValue(undefined),
        createSpan: jest.fn().mockReturnValue(mockSpan),
        recordMetric: jest.fn(),
        log: jest.fn(),
        isReady: jest.fn().mockReturnValue(true),
        shutdown: jest.fn().mockResolvedValue(undefined),
      };

      const middleware = new OpenTelemetryMiddleware({
        provider: mockProvider,
        enabled: true,
        extractAttributes: (ctx) => ({
          customField: 'custom-value',
          userId: (ctx.user as any)?.id || 'anonymous',
        }),
      });

      await middleware.before(context);

      expect(mockSpan.setAttributes).toHaveBeenCalledWith({
        customField: 'custom-value',
        userId: 'anonymous',
      });
    });
  });

  describe('X-Trace-Id header injection', () => {
    beforeEach(() => {
      // Setup mock OTEL API
      mockOtelApi = {
        context: {
          active: jest.fn(),
        },
        trace: {
          getSpan: jest.fn(),
        },
        propagation: {
          extract: jest.fn(),
        },
      };
    });

    it('should add X-Trace-Id header in after hook', async () => {
      const mockSpan: GenericSpan = {
        setAttributes: jest.fn(),
        recordException: jest.fn(),
        setStatus: jest.fn(),
        end: jest.fn(),
      };

      // Setup mock to return trace ID
      mockOtelApi.context.active.mockReturnValue({});
      mockOtelApi.trace.getSpan.mockReturnValue({
        spanContext: () => ({
          traceId: '0af7651916cd43dd8448eb211c80319c',
          spanId: 'b7ad6b7169203331',
        }),
      });

      const mockProvider: TelemetryProvider = {
        name: 'mock',
        validate: jest.fn().mockResolvedValue({ valid: true }),
        initialize: jest.fn().mockResolvedValue(undefined),
        createSpan: jest.fn().mockReturnValue(mockSpan),
        recordMetric: jest.fn(),
        log: jest.fn(),
        isReady: jest.fn().mockReturnValue(true),
        shutdown: jest.fn().mockResolvedValue(undefined),
      };

      const middleware = new OpenTelemetryMiddleware({
        provider: mockProvider,
        enabled: true,
      });

      // Before hook
      await middleware.before(context);

      // After hook
      await middleware.after(context);

      expect(context.res.header).toHaveBeenCalledWith(
        'X-Trace-Id',
        '0af7651916cd43dd8448eb211c80319c'
      );
    });

    it('should handle missing trace ID gracefully', async () => {
      const mockSpan: GenericSpan = {
        setAttributes: jest.fn(),
        recordException: jest.fn(),
        setStatus: jest.fn(),
        end: jest.fn(),
      };

      // Setup mock with no trace ID
      mockOtelApi.context.active.mockReturnValue({});
      mockOtelApi.trace.getSpan.mockReturnValue({
        spanContext: () => ({
          traceId: undefined,
        }),
      });

      const mockProvider: TelemetryProvider = {
        name: 'mock',
        validate: jest.fn().mockResolvedValue({ valid: true }),
        initialize: jest.fn().mockResolvedValue(undefined),
        createSpan: jest.fn().mockReturnValue(mockSpan),
        recordMetric: jest.fn(),
        log: jest.fn(),
        isReady: jest.fn().mockReturnValue(true),
        shutdown: jest.fn().mockResolvedValue(undefined),
      };

      const middleware = new OpenTelemetryMiddleware({
        provider: mockProvider,
      });

      await middleware.before(context);
      await middleware.after(context);

      // Should not add header when trace ID is missing
      expect(context.res.header).not.toHaveBeenCalledWith(
        'X-Trace-Id',
        expect.anything()
      );
    });

    it('should warn when X-Trace-Id injection fails', async () => {
      const mockSpan: GenericSpan = {
        setAttributes: jest.fn(),
        recordException: jest.fn(),
        setStatus: jest.fn(),
        end: jest.fn(),
      };

      // Make trace API throw
      mockOtelApi.trace.getSpan.mockImplementation(() => {
        throw new Error('Cannot get span');
      });

      const mockProvider: TelemetryProvider = {
        name: 'mock',
        validate: jest.fn().mockResolvedValue({ valid: true }),
        initialize: jest.fn().mockResolvedValue(undefined),
        createSpan: jest.fn().mockReturnValue(mockSpan),
        recordMetric: jest.fn(),
        log: jest.fn(),
        isReady: jest.fn().mockReturnValue(true),
        shutdown: jest.fn().mockResolvedValue(undefined),
      };

      const middleware = new OpenTelemetryMiddleware({
        provider: mockProvider,
        enabled: true,
      });

      await middleware.before(context);
      context.businessData.set('otel_span', mockSpan);
      await middleware.after(context);

      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('Failed to add X-Trace-Id header'),
        expect.anything()
      );
    });
  });

  describe('after hook', () => {
    it('should set response attributes and end span', async () => {
      const mockSpan: GenericSpan = {
        setAttributes: jest.fn(),
        recordException: jest.fn(),
        setStatus: jest.fn(),
        end: jest.fn(),
      };

      context.businessData.set('otel_span', mockSpan);
      context.res.statusCode = 200;

      const mockProvider: TelemetryProvider = {
        name: 'mock',
        validate: jest.fn().mockResolvedValue({ valid: true }),
        initialize: jest.fn().mockResolvedValue(undefined),
        createSpan: jest.fn(),
        recordMetric: jest.fn(),
        log: jest.fn(),
        isReady: jest.fn().mockReturnValue(true),
        shutdown: jest.fn().mockResolvedValue(undefined),
      };

      const middleware = new OpenTelemetryMiddleware({
        provider: mockProvider,
        enabled: true,
      });
      await middleware.after(context);

      expect(mockSpan.setAttributes).toHaveBeenCalledWith({
        'http.status_code': 200,
        'request.duration_ms': expect.any(Number),
      });
      expect(mockSpan.setStatus).toHaveBeenCalledWith({ code: 0 });
      expect(mockSpan.end).toHaveBeenCalled();
    });

    it('should handle missing span gracefully', async () => {
      const middleware = new OpenTelemetryMiddleware({
        provider: new NoopProvider(),
        enabled: true,
      });

      await expect(middleware.after(context)).resolves.not.toThrow();
    });

    it('should use default status code 200 when not set', async () => {
      const mockSpan: GenericSpan = {
        setAttributes: jest.fn(),
        recordException: jest.fn(),
        setStatus: jest.fn(),
        end: jest.fn(),
      };

      context.businessData.set('otel_span', mockSpan);
      context.res.statusCode = undefined;

      const mockProvider: TelemetryProvider = {
        name: 'mock',
        validate: jest.fn().mockResolvedValue({ valid: true }),
        initialize: jest.fn().mockResolvedValue(undefined),
        createSpan: jest.fn(),
        recordMetric: jest.fn(),
        log: jest.fn(),
        isReady: jest.fn().mockReturnValue(true),
        shutdown: jest.fn().mockResolvedValue(undefined),
      };

      const middleware = new OpenTelemetryMiddleware({
        provider: mockProvider,
        enabled: true,
      });
      await middleware.after(context);

      expect(mockSpan.setAttributes).toHaveBeenCalledWith(
        expect.objectContaining({
          'http.status_code': 200,
        })
      );
    });
  });

  describe('onError hook', () => {
    it('should record exception and set error status', async () => {
      const mockSpan: GenericSpan = {
        setAttributes: jest.fn(),
        recordException: jest.fn(),
        setStatus: jest.fn(),
        end: jest.fn(),
      };

      context.businessData.set('otel_span', mockSpan);

      const error = new Error('Test error');
      const mockProvider: TelemetryProvider = {
        name: 'mock',
        validate: jest.fn().mockResolvedValue({ valid: true }),
        initialize: jest.fn().mockResolvedValue(undefined),
        createSpan: jest.fn(),
        recordMetric: jest.fn(),
        log: jest.fn(),
        isReady: jest.fn().mockReturnValue(true),
        shutdown: jest.fn().mockResolvedValue(undefined),
      };

      const middleware = new OpenTelemetryMiddleware({
        provider: mockProvider,
        enabled: true,
      });

      await middleware.onError(error, context);

      expect(mockSpan.recordException).toHaveBeenCalledWith(error);
      expect(mockSpan.setStatus).toHaveBeenCalledWith({
        code: 1,
        message: 'Test error',
      });
      expect(mockSpan.end).toHaveBeenCalled();
    });

    it('should handle missing span in onError', async () => {
      const error = new Error('Test error');
      const middleware = new OpenTelemetryMiddleware({
        provider: new NoopProvider(),
        enabled: true,
      });

      await expect(middleware.onError(error, context)).resolves.not.toThrow();
    });

    it('should call custom onError handler', async () => {
      const mockSpan: GenericSpan = {
        setAttributes: jest.fn(),
        recordException: jest.fn(),
        setStatus: jest.fn(),
        end: jest.fn(),
      };

      context.businessData.set('otel_span', mockSpan);

      const customErrorHandler = jest.fn();
      const error = new Error('Custom error');

      const mockProvider: TelemetryProvider = {
        name: 'mock',
        validate: jest.fn().mockResolvedValue({ valid: true }),
        initialize: jest.fn().mockResolvedValue(undefined),
        createSpan: jest.fn(),
        recordMetric: jest.fn(),
        log: jest.fn(),
        isReady: jest.fn().mockReturnValue(true),
        shutdown: jest.fn().mockResolvedValue(undefined),
      };

      const middleware = new OpenTelemetryMiddleware({
        provider: mockProvider,
        enabled: true,
        onError: customErrorHandler,
      });

      await middleware.onError(error, context);

      expect(customErrorHandler).toHaveBeenCalledWith(error, context);
    });

    it('should not throw when failSilently=true', async () => {
      const error = new Error('Test error');

      const middleware = new OpenTelemetryMiddleware({
        provider: new NoopProvider(),
        enabled: true,
        failSilently: true,
      });

      await expect(middleware.onError(error, context)).resolves.not.toThrow();
    });
  });

  describe('Pub/Sub trace propagation', () => {
    beforeEach(() => {
      // Setup mock OTEL API for Pub/Sub tests
      mockOtelApi = {
        context: {
          active: jest.fn().mockReturnValue({}),
        },
        trace: {
          getSpan: jest.fn().mockReturnValue(null),
        },
        propagation: {
          extract: jest.fn().mockReturnValue({}),
        },
      };
    });

    it('should extract trace context from Pub/Sub message', async () => {
      const pubsubContext = {
        ...context,
        req: {
          ...context.req,
          body: {
            message: {
              data: Buffer.from(JSON.stringify({ test: 'data' })).toString(
                'base64'
              ),
              attributes: {
                traceparent:
                  '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
                tracestate: 'vendor=value',
              },
            },
          },
        },
      } as any;

      const mockSpan: GenericSpan = {
        setAttributes: jest.fn(),
        recordException: jest.fn(),
        setStatus: jest.fn(),
        end: jest.fn(),
      };

      const mockProvider: TelemetryProvider = {
        name: 'mock',
        validate: jest.fn().mockResolvedValue({ valid: true }),
        initialize: jest.fn().mockResolvedValue(undefined),
        createSpan: jest.fn().mockReturnValue(mockSpan),
        recordMetric: jest.fn(),
        log: jest.fn(),
        isReady: jest.fn().mockReturnValue(true),
        shutdown: jest.fn().mockResolvedValue(undefined),
      };

      const middleware = new OpenTelemetryMiddleware({
        provider: mockProvider,
        enabled: true,
        propagatePubSubTraces: true,
      });

      await middleware.before(pubsubContext);

      // Trace context extraction happens and is logged
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('[Telemetry] Extracted Pub/Sub trace context'),
        expect.objectContaining({
          traceparent:
            '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
          tracestate: 'vendor=value',
        })
      );

      // Should set messaging attributes on span
      expect(mockSpan.setAttributes).toHaveBeenCalledWith(
        expect.objectContaining({
          'messaging.system': 'pubsub',
          'messaging.operation': 'process',
        })
      );
    });

    it('should not extract trace context when propagatePubSubTraces=false', async () => {
      const pubsubContext = {
        ...context,
        req: {
          ...context.req,
          body: {
            message: {
              data: Buffer.from(JSON.stringify({ test: 'data' })).toString(
                'base64'
              ),
              attributes: {
                traceparent:
                  '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
              },
            },
          },
        },
      } as any;

      const middleware = new OpenTelemetryMiddleware({
        provider: new NoopProvider(),
        propagatePubSubTraces: false,
      });

      await middleware.before(pubsubContext);

      // Should not log trace context extraction
      expect(console.log).not.toHaveBeenCalledWith(
        expect.stringContaining('[Telemetry] Extracted Pub/Sub trace context'),
        expect.anything()
      );
    });
  });

  describe('error handling', () => {
    it('should not throw errors when failSilently=true (default)', async () => {
      const errorProvider: TelemetryProvider = {
        name: 'error',
        validate: jest.fn().mockResolvedValue({ valid: true }),
        initialize: jest.fn().mockRejectedValue(new Error('Init failed')),
        createSpan: jest.fn(),
        recordMetric: jest.fn(),
        log: jest.fn(),
        isReady: jest.fn().mockReturnValue(false),
        shutdown: jest.fn().mockResolvedValue(undefined),
      };

      const middleware = new OpenTelemetryMiddleware({
        provider: errorProvider,
        failSilently: true,
      });

      await expect(middleware.before(context)).resolves.not.toThrow();
    });

    it('should log errors to console when failSilently=true', async () => {
      // Clear previous console mocks
      (console.error as jest.Mock).mockClear();

      const errorProvider: TelemetryProvider = {
        name: 'error',
        validate: jest.fn().mockResolvedValue({ valid: true }),
        initialize: jest.fn().mockResolvedValue(undefined),
        createSpan: jest.fn().mockImplementation(() => {
          throw new Error('Span creation failed');
        }),
        recordMetric: jest.fn(),
        log: jest.fn(),
        isReady: jest.fn().mockReturnValue(true),
        shutdown: jest.fn().mockResolvedValue(undefined),
      };

      const middleware = new OpenTelemetryMiddleware({
        provider: errorProvider,
        failSilently: true,
        enabled: true,
      });

      await middleware.before(context);

      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('[Telemetry] Error'),
        expect.anything()
      );
    });
  });
});
