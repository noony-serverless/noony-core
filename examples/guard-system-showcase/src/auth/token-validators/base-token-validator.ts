/**
 * Base Token Validator
 *
 * Abstract base class for all token validation implementations in the
 * Guard System Showcase. Provides common functionality and establishes
 * the contract that all token validators must follow.
 *
 * @module BaseTokenValidator
 * @version 1.0.0
 */

import { TokenValidator } from '@noony-serverless/core';
import {
  TokenPayload,
  TokenValidationResult,
  AuthProviderType,
} from '@/types/auth.types';

/**
 * Token validator statistics for monitoring
 */
export interface TokenValidatorStats {
  /** Total validation attempts */
  totalValidations: number;

  /** Successful validations */
  successfulValidations: number;

  /** Failed validations */
  failedValidations: number;

  /** Average validation time in microseconds */
  averageValidationTimeUs: number;

  /** Cache hit count */
  cacheHits: number;

  /** Cache miss count */
  cacheMisses: number;

  /** Last validation timestamp */
  lastValidation: number;
}

/**
 * Abstract Base Token Validator
 *
 * Provides common functionality for all token validator implementations:
 * - Performance tracking and statistics collection
 * - Caching support (implementation-specific)
 * - Error handling and logging
 * - Validation result formatting
 * - Token extraction and parsing utilities
 */
export abstract class BaseTokenValidator implements TokenValidator {
  protected readonly providerType: AuthProviderType;
  protected stats: TokenValidatorStats;

  constructor(providerType: AuthProviderType) {
    this.providerType = providerType;
    this.stats = {
      totalValidations: 0,
      successfulValidations: 0,
      failedValidations: 0,
      averageValidationTimeUs: 0,
      cacheHits: 0,
      cacheMisses: 0,
      lastValidation: 0,
    };
  }

  // ============================================================================
  // CORE VALIDATION METHODS (implement in subclasses)
  // ============================================================================

  /**
   * Validate and decode a token
   *
   * Each implementation should:
   * 1. Check token format and structure
   * 2. Verify token signature/authenticity
   * 3. Check expiration and timing
   * 4. Extract and validate claims
   * 5. Return structured result
   *
   * @param token - Raw token string to validate
   * @returns Promise resolving to validation result
   */
  abstract validateToken(token: string): Promise<TokenValidationResult>;

  /**
   * Extract user ID from decoded token payload
   *
   * @param decoded - Decoded token payload
   * @returns User ID string
   */
  abstract extractUserId(decoded: TokenPayload): string;

  /**
   * Check if token is expired based on standard claims
   *
   * @param decoded - Decoded token payload
   * @returns True if token is expired
   */
  public isTokenExpired(decoded: TokenPayload): boolean {
    const now = Math.floor(Date.now() / 1000);

    // Check 'exp' (expiration time) claim
    if (decoded.exp && decoded.exp <= now) {
      return true;
    }

    // Check 'nbf' (not before) claim
    if (decoded.nbf && decoded.nbf > now) {
      return true;
    }

    return false;
  }

  // ============================================================================
  // PERFORMANCE TRACKING AND STATISTICS
  // ============================================================================

  /**
   * Track validation attempt and update statistics
   *
   * @param success - Whether validation was successful
   * @param durationUs - Validation duration in microseconds
   * @param cached - Whether result was served from cache
   */
  protected trackValidation(
    success: boolean,
    durationUs: number,
    cached = false
  ): void {
    this.stats.totalValidations++;
    this.stats.lastValidation = Date.now();

    if (success) {
      this.stats.successfulValidations++;
    } else {
      this.stats.failedValidations++;
    }

    if (cached) {
      this.stats.cacheHits++;
    } else {
      this.stats.cacheMisses++;
    }

    // Update average validation time using running average
    const totalTime =
      this.stats.averageValidationTimeUs * (this.stats.totalValidations - 1) +
      durationUs;
    this.stats.averageValidationTimeUs =
      totalTime / this.stats.totalValidations;
  }

  /**
   * Get current validation statistics
   */
  public getStats(): TokenValidatorStats {
    return { ...this.stats };
  }

  /**
   * Reset validation statistics
   */
  public resetStats(): void {
    this.stats = {
      totalValidations: 0,
      successfulValidations: 0,
      failedValidations: 0,
      averageValidationTimeUs: 0,
      cacheHits: 0,
      cacheMisses: 0,
      lastValidation: 0,
    };
  }

  /**
   * Get validation success rate as percentage
   */
  public getSuccessRate(): number {
    if (this.stats.totalValidations === 0) return 100;
    return (
      (this.stats.successfulValidations / this.stats.totalValidations) * 100
    );
  }

  /**
   * Get cache hit rate as percentage
   */
  public getCacheHitRate(): number {
    const totalCacheAttempts = this.stats.cacheHits + this.stats.cacheMisses;
    if (totalCacheAttempts === 0) return 0;
    return (this.stats.cacheHits / totalCacheAttempts) * 100;
  }

  // ============================================================================
  // UTILITY METHODS
  // ============================================================================

  /**
   * Safely parse a JWT token without validation
   *
   * @param token - JWT token string
   * @returns Decoded payload or null if invalid format
   */
  protected safeParseJWT(token: string): TokenPayload | null {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return null;
      }

      const payload = parts[1];
      const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString());
      return decoded as TokenPayload;
    } catch {
      return null;
    }
  }

  /**
   * Validate token format (basic JWT structure check)
   *
   * @param token - Token string to validate
   * @returns True if format is valid
   */
  protected isValidTokenFormat(token: string): boolean {
    if (!token || typeof token !== 'string') {
      return false;
    }

    // Basic JWT format check (3 base64url-encoded parts separated by dots)
    const parts = token.split('.');
    if (parts.length !== 3) {
      return false;
    }

    // Check that each part is valid base64url
    try {
      for (const part of parts) {
        Buffer.from(part, 'base64url');
      }
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Create standardized validation result
   *
   * @param valid - Whether validation passed
   * @param decoded - Decoded token payload (if valid)
   * @param error - Error message (if invalid)
   * @param validationTimeUs - Time taken for validation
   * @param cached - Whether result was cached
   * @returns Formatted validation result
   */
  protected createValidationResult(
    valid: boolean,
    decoded?: TokenPayload,
    error?: string,
    validationTimeUs = 0,
    cached = false
  ): TokenValidationResult {
    return {
      valid,
      decoded: valid ? decoded : undefined,
      error: valid ? undefined : error,
      metadata: {
        validationTimeUs,
        cached,
        validatorType: this.getValidatorType(),
      },
    };
  }

  /**
   * Get the validator type identifier
   */
  public getValidatorType(): string {
    return this.providerType;
  }

  /**
   * Get human-readable validator name
   */
  public getValidatorName(): string {
    switch (this.providerType) {
      case AuthProviderType.JWT:
        return 'JSON Web Token Validator';
      case AuthProviderType.FIREBASE:
        return 'Firebase Authentication Validator';
      case AuthProviderType.AUTH0:
        return 'Auth0 Token Validator';
      case AuthProviderType.CUSTOM:
        return 'Custom Token Validator';
      default:
        return 'Unknown Token Validator';
    }
  }

  // ============================================================================
  // CACHING UTILITIES (override in subclasses if needed)
  // ============================================================================

  /**
   * Generate cache key for token validation result
   *
   * @param token - Token string
   * @returns Cache key string
   */
  protected getCacheKey(token: string): string {
    // Use first 8 and last 8 characters for security
    const tokenHash =
      token.length > 16
        ? `${token.substring(0, 8)}...${token.substring(token.length - 8)}`
        : 'short-token';

    return `token-validation:${this.providerType}:${tokenHash}`;
  }

  /**
   * Check if validation result should be cached
   *
   * @param result - Validation result
   * @returns True if result should be cached
   */
  protected shouldCacheResult(result: TokenValidationResult): boolean {
    // Generally cache successful validations
    // Don't cache temporary failures that might resolve
    return result.valid;
  }

  /**
   * Get cache TTL for validation results
   *
   * @param decoded - Decoded token payload
   * @returns TTL in milliseconds
   */
  protected getCacheTTL(decoded?: TokenPayload): number {
    if (!decoded || !decoded.exp) {
      // Default 5 minute cache for tokens without expiration
      return 5 * 60 * 1000;
    }

    // Cache until halfway to token expiration
    const now = Math.floor(Date.now() / 1000);
    const timeToExpiry = decoded.exp - now;
    const cacheDuration = Math.floor(timeToExpiry / 2);

    // Ensure cache duration is between 1 minute and 30 minutes
    return Math.max(60, Math.min(cacheDuration * 1000, 30 * 60 * 1000));
  }

  // ============================================================================
  // LOGGING AND DEBUGGING
  // ============================================================================

  /**
   * Log validation attempt (for debugging and monitoring)
   *
   * @param token - Token being validated (will be safely logged)
   * @param result - Validation result
   * @param error - Any error that occurred
   */
  protected logValidation(
    token: string,
    result: TokenValidationResult,
    error?: Error
  ): void {
    const safeToken =
      token.length > 16
        ? `${token.substring(0, 8)}...${token.substring(token.length - 8)}`
        : '[short-token]';

    if (result.valid) {
      console.debug(`✅ Token validation success [${this.providerType}]:`, {
        token: safeToken,
        userId: result.decoded?.sub,
        validationTime: `${result.metadata?.validationTimeUs || 0}μs`,
        cached: result.metadata?.cached || false,
      });
    } else {
      console.warn(`❌ Token validation failed [${this.providerType}]:`, {
        token: safeToken,
        error: result.error,
        validationTime: `${result.metadata?.validationTimeUs || 0}μs`,
        actualError: error?.message,
      });
    }
  }

  /**
   * Create validation error with context
   *
   * @param message - Error message
   * @param code - Error code
   * @param details - Additional error details
   * @returns Error object with context
   */
  protected createValidationError(
    message: string,
    code: string,
    details?: Record<string, unknown>
  ): Error {
    const error = new Error(`[${this.providerType}] ${message}`);
    (error as any).code = code;
    (error as any).provider = this.providerType;
    (error as any).details = details;
    return error;
  }
}
