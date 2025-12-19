/**
 * Cloud Run Optimized Server Example
 *
 * This example demonstrates the COMPLETE OpenTelemetry setup for Google Cloud Run
 * with automatic initialization, aggressive span export, and distributed tracing.
 *
 * CRITICAL: Import order matters! telemetry.config.ts MUST be imported first
 * to ensure OTEL instrumentation hooks are registered before any other libraries.
 *
 * Features:
 * - Auto-initialization of OTEL SDK at module load
 * - Aggressive span processor (100ms interval, batch size 1)
 * - HTTP auto-instrumentation (creates root spans automatically)
 * - MongoDB/Pino instrumentation
 * - Fastify instrumentation disabled (prevents duplicates)
 * - CloudPropagator + W3C composite propagation
 * - Graceful shutdown with force flush
 * - Logger with automatic trace/span ID injection
 */

// ============================================================================
// CRITICAL: Import OTEL configuration FIRST
// This MUST be the first import to ensure instrumentation hooks are registered
// before Fastify, MongoDB, and other libraries are loaded.
// ============================================================================
import '@config/telemetry.config';

import 'reflect-metadata';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import { logger } from '@/core/logger';

/**
 * Create Fastify server with CORS support
 */
const app = Fastify({
  logger: false, // Use custom logger with OTEL integration
});

/**
 * IMPORTANT: Do NOT register @fastify/otel as a plugin
 *
 * HTTP instrumentation (from telemetry.config.ts) already creates root spans
 * for all HTTP requests. Registering @fastify/otel would cause duplicate spans
 * and massive latency (9+ seconds).
 *
 * See: https://github.com/open-telemetry/opentelemetry-js-contrib/issues/1416
 */

/**
 * Setup middleware
 */
app.register(cors, {
  origin: true,
  credentials: true,
});

/**
 * Health check endpoint (ignored by OTEL instrumentation)
 */
app.get('/health', async () => {
  return { status: 'healthy', timestamp: new Date().toISOString() };
});

/**
 * Example endpoint with automatic tracing
 *
 * HTTP instrumentation automatically:
 * 1. Creates a root span for this request
 * 2. Extracts trace context from X-Cloud-Trace-Context header (if present)
 * 3. Propagates trace context to downstream calls
 * 4. Records span to Cloud Trace (exported every 100ms)
 *
 * Logger automatically includes traceId/spanId in all logs.
 */
app.get('/api/users/:id', async (request, _reply) => {
  const userId = (request.params as { id: string }).id;

  // Logger automatically includes trace/span IDs
  logger.info('Fetching user', { userId });

  // Simulate database query (MongoDB instrumentation would trace this)
  const user = {
    id: userId,
    name: 'John Doe',
    email: 'john@example.com',
    createdAt: new Date().toISOString(),
  };

  logger.info('User fetched successfully', { userId });

  return { data: user };
});

/**
 * Example endpoint demonstrating error tracking
 */
app.get('/api/error', async () => {
  // This error will be automatically:
  // 1. Recorded in the active span
  // 2. Logged with trace/span IDs
  // 3. Sent to Cloud Trace with error status
  logger.error('Simulating an error');
  throw new Error('This is a test error for distributed tracing');
});

/**
 * Example endpoint demonstrating manual span creation
 *
 * While HTTP instrumentation creates root spans automatically,
 * you can create child spans for specific operations.
 */
app.post('/api/orders', async (request, _reply) => {
  // Get tracer from OTEL API
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { trace } = require('@opentelemetry/api');
  const tracer = trace.getTracer('order-service');

  // Create child span for order processing
  const span = tracer.startSpan('process-order');

  try {
    const orderData = request.body as Record<string, unknown>;
    logger.info('Processing order', { orderData });

    // Simulate order processing
    span.setAttribute('order.id', orderData.orderId || 'unknown');
    span.setAttribute('order.total', orderData.total || 0);

    // Simulate async processing
    await new Promise((resolve) => setTimeout(resolve, 100));

    logger.info('Order processed successfully');

    span.setStatus({ code: 1 }); // OK
    return { success: true, orderId: orderData.orderId };
  } catch (error) {
    // Record exception in span
    span.recordException(error as Error);
    span.setStatus({ code: 2, message: (error as Error).message }); // ERROR
    logger.error('Order processing failed', {
      error: (error as Error).message,
    });
    throw error;
  } finally {
    span.end();
  }
});

/**
 * Start server
 */
const PORT = parseInt(process.env.PORT || '8080', 10);
const HOST = process.env.HOST || '0.0.0.0';

app.listen({ port: PORT, host: HOST }, (err, address) => {
  if (err) {
    logger.error('Failed to start server', { error: err.message });
    process.exit(1);
  }
  logger.info('Server started', { address, port: PORT });
  logger.info('OpenTelemetry SDK initialized - traces sent to Cloud Trace');
});

/**
 * Graceful shutdown
 *
 * The telemetry.config.ts file automatically registers SIGTERM/SIGINT handlers
 * that force flush pending spans before shutdown. No additional code needed here.
 */
