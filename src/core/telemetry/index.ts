/**
 * Telemetry Module
 *
 * Provides OpenTelemetry integration for the Noony framework with:
 * - Extensible provider system (OTEL, New Relic, Datadog, Console, Noop)
 * - Auto-detection from environment variables
 * - Graceful degradation when configuration is missing
 * - Zero-configuration local development support
 *
 * @example
 * import { OpenTelemetryMiddleware } from '@noony-serverless/core';
 *
 * const handler = new Handler()
 *   .use(new OpenTelemetryMiddleware()) // Auto-detects provider
 *   .handle(async (context) => {
 *     // Your business logic
 *   });
 */

// Core interfaces and types
export * from './provider';

// Configuration and presets (explicit exports to avoid conflict)
export {
  TelemetryPresets,
  isRunningOnGCP,
  getDefaultTelemetryConfig,
} from './config';

// Provider implementations
export * from './providers';
