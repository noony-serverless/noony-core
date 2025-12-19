/**
 * Cloud Run Async Processor Example (Pub/Sub Consumer)
 *
 * This example demonstrates distributed tracing across Pub/Sub messages.
 * When a message is published with trace context, this processor continues
 * the same distributed trace for end-to-end observability.
 *
 * Architecture:
 * 1. Publisher (server.ts) → Injects trace context into Pub/Sub message attributes
 * 2. Pub/Sub → Delivers message with trace context
 * 3. Consumer (this file) → Extracts trace context and continues the trace
 *
 * CRITICAL: Import order matters! telemetry.config.ts MUST be imported first.
 */

// ============================================================================
// CRITICAL: Import OTEL configuration FIRST
// ============================================================================
import '@config/telemetry.config';

import 'reflect-metadata';
import { PubSub, Message } from '@google-cloud/pubsub';
import { context, propagation, trace } from '@opentelemetry/api';
import { logger } from '@/core/logger';

/**
 * Initialize Pub/Sub client
 */
const pubsub = new PubSub({
  projectId: process.env.GOOGLE_CLOUD_PROJECT || process.env.GCP_PROJECT,
});

const SUBSCRIPTION_NAME = process.env.SUBSCRIPTION_NAME || 'order-events-sub';

/**
 * Process incoming Pub/Sub message with distributed tracing
 *
 * This function:
 * 1. Extracts trace context from message attributes (injected by publisher)
 * 2. Creates a new OTEL context with the extracted trace
 * 3. Executes business logic within that trace context
 * 4. All spans/logs automatically use the same trace ID as the publisher
 */
async function processMessage(message: Message): Promise<void> {
  // Extract trace context from Pub/Sub message attributes
  // The publisher injected this using propagation.inject()
  const extractedContext = propagation.extract(
    context.active(),
    message.attributes
  );

  // Execute processing within the extracted trace context
  // This ensures all operations continue the distributed trace
  return context.with(extractedContext, async () => {
    // Get trace ID for logging
    const activeSpan = trace.getSpan(extractedContext);
    const traceId = activeSpan?.spanContext().traceId;

    logger.info('Processing Pub/Sub message', {
      messageId: message.id,
      traceId, // Same trace ID as publisher!
      attributes: message.attributes,
    });

    try {
      // Parse message data
      const data = JSON.parse(message.data.toString());
      logger.info('Message data parsed', { data, traceId });

      // Create child span for specific processing
      const tracer = trace.getTracer('async-processor');
      const span = tracer.startSpan('process-job');

      try {
        span.setAttribute('job.type', data.type || 'unknown');
        span.setAttribute('job.id', data.jobId || 'unknown');

        // Simulate job processing
        await processJob(data);

        span.setStatus({ code: 1 }); // OK
        logger.info('Job processed successfully', {
          jobId: data.jobId,
          traceId,
        });

        // Acknowledge message
        message.ack();
      } catch (error) {
        span.recordException(error as Error);
        span.setStatus({ code: 2, message: (error as Error).message });
        logger.error('Job processing failed', {
          error: (error as Error).message,
          traceId,
        });

        // Nack message for retry
        message.nack();
      } finally {
        span.end();
      }
    } catch (error) {
      logger.error('Failed to parse message data', {
        error: (error as Error).message,
        traceId,
      });
      message.nack();
    }
  });
}

/**
 * Simulate job processing
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function processJob(data: any): Promise<void> {
  // Get current tracer
  const tracer = trace.getTracer('async-processor');
  const span = tracer.startSpan('job-execution');

  try {
    logger.info('Executing job', { type: data.type, jobId: data.jobId });

    // Simulate work
    await new Promise((resolve) => setTimeout(resolve, 200));

    span.setStatus({ code: 1 });
    logger.info('Job executed', { jobId: data.jobId });
  } catch (error) {
    span.recordException(error as Error);
    span.setStatus({ code: 2 });
    throw error;
  } finally {
    span.end();
  }
}

/**
 * Start subscription
 */
async function startSubscription(): Promise<void> {
  logger.info('Starting Pub/Sub subscription', {
    subscription: SUBSCRIPTION_NAME,
  });

  const subscription = pubsub.subscription(SUBSCRIPTION_NAME);

  // Configure subscription settings
  subscription.on('message', processMessage);

  subscription.on('error', (error) => {
    logger.error('Subscription error', { error: error.message });
  });

  logger.info('Subscription active - waiting for messages');
}

/**
 * Main entry point
 */
startSubscription().catch((error) => {
  logger.error('Failed to start subscription', { error: error.message });
  process.exit(1);
});

/**
 * Graceful shutdown
 *
 * The telemetry.config.ts file automatically registers SIGTERM/SIGINT handlers
 * that force flush pending spans before shutdown.
 */
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received - shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received - shutting down gracefully');
  process.exit(0);
});
