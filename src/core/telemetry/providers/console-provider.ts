import { Context } from '../../core';
import {
  TelemetryProvider,
  ValidationResult,
  GenericSpan,
  TelemetryConfig,
} from '../provider';

/**
 * Console Telemetry Provider
 *
 * Logs all telemetry data to the console for local development and debugging.
 * This provider is useful for:
 * 1. Local development without external telemetry infrastructure
 * 2. Debugging telemetry integration
 * 3. Testing span creation and attributes
 *
 * Auto-selected when NODE_ENV=development and no OTEL endpoint is configured.
 *
 * @example
 * // Auto-detected in development
 * NODE_ENV=development
 *
 * // Or explicitly configured
 * const provider = new ConsoleProvider();
 * await provider.initialize({ serviceName: 'my-service' });
 */
export class ConsoleProvider implements TelemetryProvider {
  readonly name = 'console';
  private enabled = false;

  /**
   * Console provider is always valid (useful for local testing)
   */
  async validate(): Promise<ValidationResult> {
    return { valid: true };
  }

  /**
   * Initialize console provider
   */
  async initialize(config: TelemetryConfig): Promise<void> {
    this.enabled = config.enabled !== false;

    if (this.enabled) {
      console.log('[Telemetry] Console provider initialized');
      console.log('[Telemetry] Service:', config.serviceName);
      console.log('[Telemetry] Version:', config.serviceVersion || 'unknown');
      console.log(
        '[Telemetry] Environment:',
        config.environment || 'development'
      );
    }
  }

  /**
   * Create a console span that logs to stdout
   */
  createSpan(context: Context<unknown, unknown>): GenericSpan | undefined {
    if (!this.enabled) return undefined;

    const spanData = {
      startTime: Date.now(),
      method: context.req.method,
      path: context.req.path || context.req.url,
      requestId: context.requestId,
    };

    console.log('[Telemetry] 🟢 Span started:', spanData);

    return {
      setAttributes: (attrs: Record<string, unknown>): void => {
        console.log('[Telemetry] 📊 Span attributes:', attrs);
      },

      recordException: (error: Error): void => {
        console.error('[Telemetry] ❌ Exception:', {
          message: error.message,
          name: error.name,
          stack: error.stack,
        });
      },

      setStatus: (status: { code: number; message?: string }): void => {
        const statusIcon = status.code === 0 ? '✅' : '⚠️';
        console.log(`[Telemetry] ${statusIcon} Span status:`, status);
      },

      end: (): void => {
        const duration = Date.now() - spanData.startTime;
        console.log('[Telemetry] 🔴 Span ended:', {
          ...spanData,
          duration: `${duration}ms`,
        });
      },
    };
  }

  /**
   * Log metric to console
   */
  recordMetric(
    name: string,
    value: number,
    attributes?: Record<string, unknown>
  ): void {
    if (!this.enabled) return;

    console.log('[Telemetry] 📈 Metric:', {
      name,
      value,
      attributes,
    });
  }

  /**
   * Log message to console with level
   */
  log(
    level: string,
    message: string,
    attributes?: Record<string, unknown>
  ): void {
    if (!this.enabled) return;

    const levelIcon =
      {
        info: 'ℹ️',
        error: '❌',
        warn: '⚠️',
        debug: '🔍',
      }[level] || '📝';

    console.log(
      `[Telemetry] ${levelIcon} Log [${level}]:`,
      message,
      attributes
    );
  }

  /**
   * Console provider is always ready if enabled
   */
  isReady(): boolean {
    return this.enabled;
  }

  /**
   * Shutdown console provider
   */
  async shutdown(): Promise<void> {
    if (this.enabled) {
      console.log('[Telemetry] Console provider shutdown');
    }
    this.enabled = false;
  }
}
