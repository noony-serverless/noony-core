import { Context } from '../../core';
import {
  TelemetryProvider,
  ValidationResult,
  GenericSpan,
  TelemetryConfig,
} from '../provider';

/**
 * Noop (No-operation) Telemetry Provider
 *
 * This provider does nothing and is used as:
 * 1. Fallback when other providers fail validation
 * 2. Default when telemetry is disabled (NODE_ENV=test)
 * 3. Placeholder when no configuration is provided
 *
 * It implements all TelemetryProvider methods as no-ops to ensure
 * the application continues to work even when telemetry fails.
 *
 * @example
 * // Automatically used as fallback
 * const provider = new NoopProvider();
 * await provider.initialize({ serviceName: 'test' });
 * const span = provider.createSpan(context); // Returns undefined
 */
export class NoopProvider implements TelemetryProvider {
  readonly name = 'noop';

  /**
   * Noop provider is always valid
   */
  async validate(): Promise<ValidationResult> {
    return { valid: true };
  }

  /**
   * No-op initialization
   */
  async initialize(_config: TelemetryConfig): Promise<void> {
    // Do nothing
  }

  /**
   * Always returns undefined (no span created)
   */
  createSpan(_context: Context<unknown, unknown>): GenericSpan | undefined {
    return undefined;
  }

  /**
   * No-op metric recording
   */
  recordMetric(
    _name: string,
    _value: number,
    _attributes?: Record<string, unknown>
  ): void {
    // Do nothing
  }

  /**
   * No-op logging
   */
  log(
    _level: string,
    _message: string,
    _attributes?: Record<string, unknown>
  ): void {
    // Do nothing
  }

  /**
   * Always ready (does nothing, so always ready)
   */
  isReady(): boolean {
    return true;
  }

  /**
   * No-op shutdown
   */
  async shutdown(): Promise<void> {
    // Do nothing
  }
}
