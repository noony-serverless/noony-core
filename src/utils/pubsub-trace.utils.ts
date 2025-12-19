import { Context } from '../core';

/**
 * Google Cloud Pub/Sub message structure
 */
export interface PubSubMessage {
  message: {
    data: string;
    publishTime?: string;
    messageId?: string;
    attributes?: Record<string, string>;
  };
}

/**
 * W3C Trace Context extracted from Pub/Sub message attributes
 */
export interface TraceContext {
  traceparent?: string;
  tracestate?: string;
}

/**
 * Type guard to check if request body is a Pub/Sub message
 *
 * @param body - Request body to check
 * @returns True if body is a Pub/Sub message
 *
 * @example
 * if (isPubSubMessage(context.req.body)) {
 *   const traceContext = extractTraceContext(context.req.body);
 * }
 */
export function isPubSubMessage(body: unknown): body is PubSubMessage {
  return (
    !!body &&
    typeof body === 'object' &&
    'message' in body &&
    typeof (body as PubSubMessage).message === 'object' &&
    'data' in (body as PubSubMessage).message
  );
}

/**
 * Extract W3C Trace Context from Pub/Sub message attributes
 *
 * Extracts the following headers from message.attributes:
 * - `traceparent`: W3C Trace Context propagation header (required)
 * - `tracestate`: Vendor-specific trace state (optional)
 *
 * @param message - Pub/Sub message
 * @returns Trace context object with traceparent and tracestate
 *
 * @example
 * const traceContext = extractTraceContext(pubsubMessage);
 * if (traceContext.traceparent) {
 *   console.log('Parent trace ID:', traceContext.traceparent);
 * }
 */
export function extractTraceContext(message: PubSubMessage): TraceContext {
  const attributes = message.message.attributes || {};

  return {
    traceparent: attributes.traceparent,
    tracestate: attributes.tracestate,
  };
}

/**
 * Inject W3C Trace Context into Pub/Sub message attributes
 *
 * Adds trace context from the current OpenTelemetry span to message attributes.
 * This enables distributed tracing across Pub/Sub publishers and subscribers.
 *
 * The trace context is extracted using OpenTelemetry's propagation API and
 * injected into the message attributes as:
 * - `traceparent`: W3C Trace Context version-traceid-spanid-flags
 * - `tracestate`: Vendor-specific trace state (if present)
 *
 * @param message - Pub/Sub message to inject trace context into
 * @param context - Noony request context (optional, used to get active span)
 * @returns Message with trace context injected into attributes
 *
 * @example
 * // Publishing a message with trace context
 * import { injectTraceContext } from '@noony-serverless/core';
 *
 * const message = {
 *   data: Buffer.from(JSON.stringify({ userId: '123' })).toString('base64'),
 *   attributes: {
 *     type: 'user.created'
 *   }
 * };
 *
 * const tracedMessage = injectTraceContext(message, context);
 * await pubsub.topic('users').publish(tracedMessage);
 *
 * @example
 * // Publishing without context (uses active span from context)
 * const tracedMessage = injectTraceContext(message);
 * await pubsub.topic('users').publish(tracedMessage);
 */
export function injectTraceContext(
  message: { data: string; attributes?: Record<string, string> },
  context?: Context<unknown, unknown>
): { data: string; attributes: Record<string, string> } {
  // Initialize attributes if not present
  const attributes = message.attributes || {};

  try {
    // Try to use OpenTelemetry API if available
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const otelApi = require('@opentelemetry/api');
    const { trace, propagation, context: otelContext } = otelApi;

    // Get current context (either from provided context or active context)
    let activeContext = otelContext.active();

    // If Noony context provided, try to get span from businessData
    if (context) {
      const span = context.businessData.get('otel_span');
      if (span && typeof span === 'object' && 'spanContext' in span) {
        // Create context with span
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        activeContext = trace.setSpan(activeContext, span as any);
      }
    }

    // Get active span if no span found in businessData
    const activeSpan = trace.getSpan(activeContext);

    if (!activeSpan) {
      // No active span, return message without trace context
      return {
        data: message.data,
        attributes,
      };
    }

    // Inject trace context into a carrier object
    const carrier: Record<string, string> = {};
    propagation.inject(activeContext, carrier);

    // Merge trace context into message attributes
    return {
      data: message.data,
      attributes: {
        ...attributes,
        ...carrier, // This adds traceparent and tracestate
      },
    };
  } catch (error) {
    // OpenTelemetry not available or error during injection
    // Return message without trace context (fail gracefully)
    console.warn('[Telemetry] Failed to inject trace context:', error);
    return {
      data: message.data,
      attributes,
    };
  }
}

/**
 * Extract trace context and create parent context for OpenTelemetry
 *
 * This is a lower-level utility used internally by OpenTelemetryMiddleware.
 * Most users should use the middleware's automatic trace propagation instead.
 *
 * @param traceContext - Extracted W3C trace context
 * @returns OpenTelemetry context with extracted trace context
 *
 * @internal
 */
export function createParentContext(
  traceContext: TraceContext
): Record<string, string> {
  if (!traceContext.traceparent) {
    return {};
  }

  const carrier: Record<string, string> = {
    traceparent: traceContext.traceparent,
  };

  if (traceContext.tracestate) {
    carrier.tracestate = traceContext.tracestate;
  }

  return carrier;
}
