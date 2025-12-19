/**
 * Telemetry Providers
 *
 * This module exports all available telemetry providers.
 * Providers can be used directly or auto-detected by OpenTelemetryMiddleware.
 */

export { NoopProvider } from './noop-provider';
export { ConsoleProvider } from './console-provider';
export { OpenTelemetryProvider } from './opentelemetry-provider';

// Note: New Relic and Datadog providers are optional and can be added when needed
// export { NewRelicProvider } from './newrelic-provider';
// export { DatadogProvider } from './datadog-provider';
