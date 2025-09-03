/**
 * Type definitions for Hello World Simple Example
 *
 * This file contains all TypeScript type definitions used throughout the example.
 * It demonstrates best practices for type safety with Zod schema validation.
 */

import { z } from 'zod';

/**
 * Zod validation schema for hello world requests
 *
 * This schema demonstrates:
 * - Required field validation (name must be at least 1 character)
 * - Optional fields with default values (greeting, includeTimestamp)
 * - String length constraints and format validation
 * - Boolean field handling with type coercion
 *
 * The schema serves dual purposes:
 * 1. Runtime validation of incoming requests
 * 2. TypeScript type generation through z.infer<>
 */
export const helloWorldSchema = z.object({
  /**
   * The name to greet - required field
   * Must be a non-empty string (minimum 1 character)
   * Maximum 100 characters to prevent abuse
   */
  name: z
    .string({ required_error: 'Name is required' })
    .min(1, 'Name must be at least 1 character long')
    .max(100, 'Name cannot exceed 100 characters')
    .trim(), // Automatically trim whitespace

  /**
   * Optional greeting prefix - defaults to "Hello"
   * Allows customization like "Hi", "Greetings", "Welcome", etc.
   * Maximum 50 characters for reasonable greetings
   */
  greeting: z
    .string()
    .max(50, 'Greeting cannot exceed 50 characters')
    .trim()
    .optional()
    .default('Hello'),

  /**
   * Whether to include timestamp in response - defaults to true
   * Useful for debugging and API monitoring
   * Can be set to false for minimal responses
   */
  includeTimestamp: z.boolean().optional().default(true),

  /**
   * Optional language code for internationalization
   * Follows ISO 639-1 standard (e.g., 'en', 'es', 'fr')
   * Currently for demonstration - not implemented in handler
   */
  language: z
    .string()
    .regex(/^[a-z]{2}$/, 'Language must be a 2-letter ISO code')
    .optional(),
});

/**
 * TypeScript type inferred from Zod schema
 *
 * This type is automatically generated and ensures:
 * - Perfect sync between validation and types
 * - Compile-time type checking
 * - IDE autocompletion and IntelliSense
 * - No manual type maintenance required
 */
export type HelloWorldRequest = z.infer<typeof helloWorldSchema>;

/**
 * Response data structure for successful hello world responses
 *
 * This interface defines the exact structure returned by the handler
 * before it gets wrapped by ResponseWrapperMiddleware
 */
export interface HelloWorldResponseData {
  /** The formatted greeting message */
  message: string;

  /**
   * Optional timestamp of when the response was generated
   * Only included when includeTimestamp is true
   */
  timestamp?: string;

  /**
   * Optional unique request identifier for debugging
   * Helps trace requests through logs and monitoring systems
   */
  requestId?: string;

  /**
   * Optional language used for the greeting
   * For future internationalization features
   */
  language?: string;
}

/**
 * Standard API response structure (after ResponseWrapperMiddleware)
 *
 * This is what the client actually receives, showing the standard
 * Noony response format with success/error indication
 */
export interface StandardApiResponse<T = any> {
  /** Indicates if the request was successful */
  success: boolean;

  /** The actual response data (HelloWorldResponseData for this example) */
  payload: T;

  /** ISO timestamp of when the response was sent */
  timestamp: string;

  /** Error message (only present when success is false) */
  error?: string;
}

/**
 * Environment configuration interface
 *
 * Defines all environment variables used by the application
 * with proper typing and documentation
 */
export interface EnvironmentConfig {
  /** Current environment (development, staging, production) */
  NODE_ENV: 'development' | 'staging' | 'production';

  /** Logging level for the application */
  LOG_LEVEL: 'debug' | 'info' | 'warn' | 'error';

  /** Port for the Functions Framework server */
  PORT: number;

  /** Enable debug mode for additional logging */
  DEBUG: boolean;

  /** Default greeting when none specified */
  DEFAULT_GREETING?: string;

  /** Enable request ID generation */
  ENABLE_REQUEST_ID?: boolean;
}

/**
 * Custom error types for this example
 *
 * Extends the base Error class with additional context
 * for better error handling and debugging
 */
export class HelloWorldError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly statusCode: number = 400
  ) {
    super(message);
    this.name = 'HelloWorldError';
  }
}

/**
 * Request context data specific to this example
 *
 * Can be stored in context.businessData for sharing
 * between middlewares in the same request
 */
export interface HelloWorldContext {
  /** Parsed and validated request data */
  validatedRequest: HelloWorldRequest;

  /** Generated request ID for tracing */
  requestId: string;

  /** Start time for performance monitoring */
  startTime: Date;

  /** User's preferred language (if detected) */
  preferredLanguage?: string;
}

/**
 * Performance metrics for monitoring
 *
 * Can be collected and sent to monitoring systems
 */
export interface RequestMetrics {
  /** Total request processing time in milliseconds */
  duration: number;

  /** Memory usage at start of request */
  memoryUsageStart: NodeJS.MemoryUsage;

  /** Memory usage at end of request */
  memoryUsageEnd: NodeJS.MemoryUsage;

  /** Request size in bytes */
  requestSize: number;

  /** Response size in bytes */
  responseSize: number;
}
