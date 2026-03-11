/**
 * Base Telemetry Provider
 * Abstract base class with default implementations for common provider patterns
 * Reduces boilerplate in provider implementations
 */

import { Context } from '../core';
import {
  TelemetryProvider,
  ValidationResult,
  GenericSpan,
  TelemetryConfig,
} from './provider';

/**
 * Base implementation of TelemetryProvider
 * Subclasses only need to override methods they want to customize
 */
export abstract class BaseProvider implements TelemetryProvider {
  abstract readonly name: string;
  protected enabled = false;

  /**
   * Validate provider configuration
   * Default: always valid
   */
  async validate(): Promise<ValidationResult> {
    return { valid: true };
  }

  /**
   * Initialize provider
   * Default: enable if not explicitly disabled
   */
  async initialize(config: TelemetryConfig): Promise<void> {
    this.enabled = config.enabled !== false;
  }

  /**
   * Check if provider is ready
   * Default: returns enabled status
   */
  isReady(): boolean {
    return this.enabled;
  }

  /**
   * Create a span for the given context
   * Subclasses must implement this
   */
  abstract createSpan(
    _context: Context<unknown, unknown>
  ): GenericSpan | undefined;

  /**
   * Record a metric
   * Default: no-op
   */
  recordMetric(
    _name: string,
    _value: number,
    _attributes?: Record<string, unknown>
  ): void {
    // Override in subclasses if needed
  }

  /**
   * Log with trace correlation
   * Default: no-op
   */
  log(
    _level: string,
    _message: string,
    _attributes?: Record<string, unknown>
  ): void {
    // Override in subclasses if needed
  }

  /**
   * Shutdown provider and flush pending data
   * Default: no-op
   */
  async shutdown(): Promise<void> {
    // Override in subclasses if needed
  }
}
