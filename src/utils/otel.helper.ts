/**
 * OpenTelemetry Helper Utilities
 *
 * Provides helper functions for integrating OpenTelemetry with logging systems.
 * These utilities enable automatic trace/span ID injection into log entries for
 * correlation with distributed traces in Cloud Logging and other observability platforms.
 *
 * @module utils/otel.helper
 */

import type { Context as OtelContext, Span } from '@opentelemetry/api';

// Conditional OpenTelemetry import (optional dependency)
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let trace: any;
try {
  const otelApi = require('@opentelemetry/api');
  trace = otelApi.trace;
} catch {
  // OpenTelemetry not installed - helpers will return empty objects
  trace = null;
}

/**
 * OTEL context object for logger integration
 */
export interface OTELLogContext {
  traceId?: string;
  spanId?: string;
  traceFlags?: number;
}

/**
 * Create Pino mixin for automatic trace/span ID injection
 *
 * This function creates a Pino mixin that automatically adds OpenTelemetry
 * trace and span IDs to every log entry. This enables log-trace correlation
 * in Cloud Logging and other observability platforms.
 *
 * Usage with Pino:
 * ```typescript
 * import pino from 'pino';
 * import { createOTELMixin } from '@noony-serverless/core';
 *
 * const logger = pino({
 *   mixin: createOTELMixin,
 *   // ... other config
 * });
 *
 * logger.info('User created'); // Automatically includes traceId, spanId, traceFlags
 * ```
 *
 * Log output example:
 * ```json
 * {
 *   "level": 30,
 *   "time": 1640000000000,
 *   "msg": "User created",
 *   "traceId": "13ea7e3c2d3b4547baaa399062df1f2d",
 *   "spanId": "1234567890123456",
 *   "traceFlags": 1
 * }
 * ```
 *
 * @returns Mixin object with trace context or empty object if no active span
 */
export const createOTELMixin = (): OTELLogContext => {
  if (!trace) {
    return {};
  }

  try {
    const span = trace.getActiveSpan();
    if (!span) {
      return {};
    }

    const spanContext = span.spanContext();
    return {
      traceId: spanContext.traceId,
      spanId: spanContext.spanId,
      traceFlags: spanContext.traceFlags,
    };
  } catch (error) {
    // Gracefully handle any errors in trace extraction
    return {};
  }
};

/**
 * Extract OTEL context from active span
 *
 * Similar to createOTELMixin but returns undefined if no span is active,
 * making it easier to conditionally add trace context.
 *
 * @returns OTEL context or undefined if no active span
 */
export const getOTELContext = (): OTELLogContext | undefined => {
  if (!trace) {
    return undefined;
  }

  try {
    const span = trace.getActiveSpan();
    if (!span) {
      return undefined;
    }

    const spanContext = span.spanContext();
    return {
      traceId: spanContext.traceId,
      spanId: spanContext.spanId,
      traceFlags: spanContext.traceFlags,
    };
  } catch (error) {
    return undefined;
  }
};

/**
 * Extract OTEL context from a specific span
 *
 * Useful when you have a reference to a span and want to extract its context
 * for logging or propagation purposes.
 *
 * @param span - The OpenTelemetry span to extract context from
 * @returns OTEL context from the span
 */
export const getOTELContextFromSpan = (span: Span): OTELLogContext => {
  try {
    const spanContext = span.spanContext();
    return {
      traceId: spanContext.traceId,
      spanId: spanContext.spanId,
      traceFlags: spanContext.traceFlags,
    };
  } catch (error) {
    return {};
  }
};

/**
 * Extract OTEL context from an OTEL Context object
 *
 * Useful when working with OTEL Context propagation (e.g., in Pub/Sub messages)
 * and you need to extract the span context for logging.
 *
 * @param context - The OpenTelemetry context to extract from
 * @returns OTEL context from the context or undefined if no span
 */
export const getOTELContextFromContext = (
  context: OtelContext
): OTELLogContext | undefined => {
  if (!trace) {
    return undefined;
  }

  try {
    const span = trace.getSpan(context);
    if (!span) {
      return undefined;
    }

    const spanContext = span.spanContext();
    return {
      traceId: spanContext.traceId,
      spanId: spanContext.spanId,
      traceFlags: spanContext.traceFlags,
    };
  } catch (error) {
    return undefined;
  }
};

/**
 * Format trace ID for Cloud Logging
 *
 * Cloud Logging expects trace IDs in a specific format:
 * projects/[PROJECT_ID]/traces/[TRACE_ID]
 *
 * This function formats a raw trace ID into the Cloud Logging format.
 *
 * @param traceId - Raw trace ID (32-character hex string)
 * @param projectId - GCP project ID (optional, defaults to GOOGLE_CLOUD_PROJECT env var)
 * @returns Formatted trace ID for Cloud Logging or undefined if inputs invalid
 */
export const formatTraceIdForCloudLogging = (
  traceId?: string,
  projectId?: string
): string | undefined => {
  if (!traceId) {
    return undefined;
  }

  const project =
    projectId || process.env.GOOGLE_CLOUD_PROJECT || process.env.GCP_PROJECT;
  if (!project) {
    return undefined;
  }

  return `projects/${project}/traces/${traceId}`;
};

/**
 * Create Cloud Logging compatible log entry
 *
 * Combines OTEL context with log metadata to create a Cloud Logging compatible
 * log entry with trace correlation.
 *
 * @param message - Log message
 * @param metadata - Additional log metadata
 * @param projectId - GCP project ID (optional)
 * @returns Cloud Logging compatible log entry
 */
export const createCloudLoggingEntry = (
  message: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  metadata: Record<string, any> = {},
  projectId?: string
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): Record<string, any> => {
  const otelContext = getOTELContext();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const entry: Record<string, any> = {
    message,
    ...metadata,
  };

  if (otelContext?.traceId) {
    entry.traceId = otelContext.traceId;
    entry.spanId = otelContext.spanId;

    // Add Cloud Logging trace reference
    const formattedTrace = formatTraceIdForCloudLogging(
      otelContext.traceId,
      projectId
    );
    if (formattedTrace) {
      entry['logging.googleapis.com/trace'] = formattedTrace;
    }

    // Add span ID for Cloud Logging correlation
    if (otelContext.spanId) {
      entry['logging.googleapis.com/spanId'] = otelContext.spanId;
    }

    // Add trace sampled flag
    if (otelContext.traceFlags !== undefined) {
      entry['logging.googleapis.com/trace_sampled'] =
        (otelContext.traceFlags & 1) === 1;
    }
  }

  return entry;
};

/**
 * Check if OpenTelemetry is available and active
 *
 * Useful for conditional OTEL feature usage in libraries and applications.
 *
 * @returns true if OTEL is available and there's an active span
 */
export const isOTELActive = (): boolean => {
  if (!trace) {
    return false;
  }

  try {
    const span = trace.getActiveSpan();
    return !!span;
  } catch {
    return false;
  }
};

/**
 * Check if OpenTelemetry SDK is installed
 *
 * @returns true if @opentelemetry/api is installed
 */
export const isOTELInstalled = (): boolean => {
  return !!trace;
};
