/**
 * JWT Token Validator
 *
 * Production-ready JWT token validation implementation for the Guard System
 * Showcase. Supports multiple signing algorithms, comprehensive validation,
 * and performance optimizations with caching.
 *
 * Features:
 * - Multiple signing algorithms (HS256, HS384, HS512, RS256, etc.)
 * - Comprehensive claim validation (iss, aud, exp, nbf, iat)
 * - Token caching for performance optimization
 * - Detailed error reporting and security logging
 * - Support for both symmetric and asymmetric keys
 *
 * @module JWTTokenValidator
 * @version 1.0.0
 */

import * as jwt from 'jsonwebtoken';
import { BaseTokenValidator } from './base-token-validator';
import {
  TokenPayload,
  TokenValidationResult,
  AuthProviderType,
  JWTAuthConfig,
} from '@/types/auth.types';

/**
 * JWT-specific configuration options
 */
export interface JWTValidatorConfig extends JWTAuthConfig {
  /** Whether to cache validation results */
  enableCaching: boolean;

  /** Cache TTL for successful validations (milliseconds) */
  cacheTTL: number;

  /** Maximum token age to accept (seconds) */
  maxTokenAge?: number;

  /** Clock tolerance for time-based claims (seconds) */
  clockTolerance: number;

  /** Whether to require 'iat' (issued at) claim */
  requireIssuedAt: boolean;

  /** Custom claim validators */
  customValidators?: Array<{
    claim: string;
    validator: (value: any, token: TokenPayload) => boolean;
    errorMessage: string;
  }>;
}

/**
 * JWT Token Validation Cache Entry
 */
interface CacheEntry {
  result: TokenValidationResult;
  expiry: number;
}

/**
 * JWT Token Validator Implementation
 *
 * Provides comprehensive JWT token validation with:
 * - Support for multiple signing algorithms and key types
 * - Extensive claim validation and custom validators
 * - Performance optimization through intelligent caching
 * - Security-focused error handling and logging
 * - Configurable validation options for different environments
 */
export class JWTTokenValidator extends BaseTokenValidator {
  private readonly config: JWTValidatorConfig;
  private readonly cache = new Map<string, CacheEntry>();
  private readonly secret: string | Buffer;
  private readonly publicKey?: string | Buffer;

  constructor(config: JWTValidatorConfig) {
    super(AuthProviderType.JWT);
    this.config = this.validateConfig(config);

    // Setup signing key(s)
    if (this.config.secret) {
      this.secret = this.config.secret;
    } else if (this.config.publicKey) {
      this.publicKey = this.config.publicKey;
      this.secret = this.config.publicKey; // For verification
    } else {
      throw this.createValidationError(
        'JWT configuration must provide either secret or publicKey',
        'CONFIG_MISSING_KEY'
      );
    }

    console.log(
      `🔑 JWT Token Validator initialized with algorithm: ${this.config.algorithm}`
    );
  }

  // ============================================================================
  // CORE VALIDATION METHODS
  // ============================================================================

  /**
   * Validate JWT token with comprehensive checks
   *
   * Performs the following validations:
   * 1. Format and structure validation
   * 2. Signature verification
   * 3. Standard claim validation (iss, aud, exp, nbf, iat)
   * 4. Custom claim validation
   * 5. Security checks (token age, etc.)
   *
   * @param token - JWT token string to validate
   * @returns Promise resolving to detailed validation result
   */
  public async validateToken(token: string): Promise<TokenValidationResult> {
    const startTime = process.hrtime.bigint();

    try {
      // Quick format validation
      if (!this.isValidTokenFormat(token)) {
        return this.handleValidationResult(
          false,
          undefined,
          'Invalid JWT token format',
          startTime
        );
      }

      // Check cache first
      if (this.config.enableCaching) {
        const cached = this.getCachedResult(token);
        if (cached) {
          this.trackValidation(
            cached.valid,
            Number(process.hrtime.bigint() - startTime) / 1000,
            true
          );
          return cached;
        }
      }

      // Perform JWT verification
      const decoded = await this.verifyJWTToken(token);
      const result = this.handleValidationResult(
        true,
        decoded,
        undefined,
        startTime
      );

      // Cache successful result
      if (this.config.enableCaching && this.shouldCacheResult(result)) {
        this.setCachedResult(token, result);
      }

      return result;
    } catch (error) {
      const errorMessage = this.extractErrorMessage(error);
      return this.handleValidationResult(
        false,
        undefined,
        errorMessage,
        startTime
      );
    }
  }

  /**
   * Extract user ID from JWT token payload
   *
   * @param decoded - JWT token payload
   * @returns User ID string
   */
  public extractUserId(decoded: TokenPayload): string {
    // Try multiple common user ID claim locations
    return (
      decoded.sub ||
      (decoded as any).userId ||
      (decoded as any).uid ||
      (decoded as any).id ||
      ''
    );
  }

  // ============================================================================
  // JWT-SPECIFIC VALIDATION LOGIC
  // ============================================================================

  /**
   * Verify JWT token signature and claims
   *
   * @param token - JWT token string
   * @returns Promise resolving to decoded payload
   * @throws Error if verification fails
   */
  private async verifyJWTToken(token: string): Promise<TokenPayload> {
    return new Promise((resolve, reject) => {
      const options: jwt.VerifyOptions = {
        algorithms: [this.config.algorithm as jwt.Algorithm],
        issuer: this.config.issuer,
        audience: this.config.audience,
        clockTolerance: this.config.clockTolerance,
        maxAge: this.config.maxTokenAge
          ? `${this.config.maxTokenAge}s`
          : undefined,
      };

      jwt.verify(token, this.secret, options, (error, decoded) => {
        if (error) {
          reject(this.createJWTError(error));
          return;
        }

        if (!decoded || typeof decoded === 'string') {
          reject(
            this.createValidationError(
              'Invalid JWT payload format',
              'INVALID_PAYLOAD'
            )
          );
          return;
        }

        const payload = decoded as TokenPayload;

        // Additional custom validations
        try {
          this.performCustomValidations(payload);
          resolve(payload);
        } catch (validationError) {
          reject(validationError);
        }
      });
    });
  }

  /**
   * Perform custom claim validations
   *
   * @param payload - JWT token payload
   * @throws Error if custom validation fails
   */
  private performCustomValidations(payload: TokenPayload): void {
    // Check required issued at claim
    if (this.config.requireIssuedAt && !payload.iat) {
      throw this.createValidationError(
        'Token missing required iat (issued at) claim',
        'MISSING_IAT'
      );
    }

    // Run custom validators
    if (this.config.customValidators) {
      for (const validator of this.config.customValidators) {
        const claimValue = (payload as any)[validator.claim];
        if (!validator.validator(claimValue, payload)) {
          throw this.createValidationError(
            validator.errorMessage,
            'CUSTOM_VALIDATION_FAILED',
            { claim: validator.claim, value: claimValue }
          );
        }
      }
    }

    // Additional security validations
    this.performSecurityValidations(payload);
  }

  /**
   * Perform additional security validations
   *
   * @param payload - JWT token payload
   * @throws Error if security validation fails
   */
  private performSecurityValidations(payload: TokenPayload): void {
    const now = Math.floor(Date.now() / 1000);

    // Check token is not too old (separate from exp claim)
    if (payload.iat && this.config.maxTokenAge) {
      const tokenAge = now - payload.iat;
      if (tokenAge > this.config.maxTokenAge) {
        throw this.createValidationError(
          `Token is too old: ${tokenAge}s (max: ${this.config.maxTokenAge}s)`,
          'TOKEN_TOO_OLD'
        );
      }
    }

    // Check for suspicious timing patterns
    if (payload.iat && payload.exp) {
      const tokenLifetime = payload.exp - payload.iat;

      // Tokens shouldn't live longer than 7 days by default
      const maxLifetime = 7 * 24 * 60 * 60; // 7 days in seconds
      if (tokenLifetime > maxLifetime) {
        throw this.createValidationError(
          `Token lifetime too long: ${tokenLifetime}s (max: ${maxLifetime}s)`,
          'TOKEN_LIFETIME_EXCESSIVE'
        );
      }

      // Tokens shouldn't be issued in the future (with tolerance)
      if (payload.iat > now + this.config.clockTolerance) {
        throw this.createValidationError(
          'Token issued in the future',
          'TOKEN_FUTURE_ISSUED'
        );
      }
    }
  }

  // ============================================================================
  // CACHING IMPLEMENTATION
  // ============================================================================

  /**
   * Get cached validation result
   *
   * @param token - JWT token string
   * @returns Cached result or null if not found/expired
   */
  private getCachedResult(token: string): TokenValidationResult | null {
    const cacheKey = this.getCacheKey(token);
    const entry = this.cache.get(cacheKey);

    if (!entry) {
      return null;
    }

    // Check if cached result is expired
    if (Date.now() > entry.expiry) {
      this.cache.delete(cacheKey);
      return null;
    }

    // Mark result as cached
    const cachedResult = { ...entry.result };
    cachedResult.metadata = {
      ...cachedResult.metadata!,
      cached: true,
    };

    return cachedResult;
  }

  /**
   * Store validation result in cache
   *
   * @param token - JWT token string
   * @param result - Validation result to cache
   */
  private setCachedResult(token: string, result: TokenValidationResult): void {
    if (!this.shouldCacheResult(result)) {
      return;
    }

    const cacheKey = this.getCacheKey(token);
    const ttl = this.getCacheTTL(result.decoded);

    this.cache.set(cacheKey, {
      result: { ...result },
      expiry: Date.now() + ttl,
    });

    // Periodic cache cleanup to prevent memory leaks
    if (this.cache.size > 10000) {
      this.cleanupCache();
    }
  }

  /**
   * Clean up expired cache entries
   */
  private cleanupCache(): void {
    const now = Date.now();
    let cleaned = 0;

    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiry) {
        this.cache.delete(key);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      console.debug(`🧹 JWT cache cleanup: removed ${cleaned} expired entries`);
    }
  }

  // ============================================================================
  // ERROR HANDLING AND UTILITIES
  // ============================================================================

  /**
   * Handle validation result and update statistics
   *
   * @param valid - Whether validation was successful
   * @param decoded - Decoded token payload
   * @param error - Error message
   * @param startTime - Validation start time
   * @returns Formatted validation result
   */
  private handleValidationResult(
    valid: boolean,
    decoded?: TokenPayload,
    error?: string,
    startTime: bigint = process.hrtime.bigint()
  ): TokenValidationResult {
    const endTime = process.hrtime.bigint();
    const validationTimeUs = Number(endTime - startTime) / 1000;

    const result = this.createValidationResult(
      valid,
      decoded,
      error,
      validationTimeUs
    );

    // Update statistics
    this.trackValidation(valid, validationTimeUs);

    // Log validation attempt
    if (process.env.NODE_ENV === 'development') {
      console.debug(`${valid ? '✅' : '❌'} JWT validation:`, {
        valid,
        userId: decoded?.sub,
        error: error,
        time: `${validationTimeUs.toFixed(1)}μs`,
      });
    }

    return result;
  }

  /**
   * Create JWT-specific error from jsonwebtoken library error
   *
   * @param jwtError - Error from jsonwebtoken library
   * @returns Standardized validation error
   */
  private createJWTError(jwtError: any): Error {
    let message = 'JWT validation failed';
    let code = 'JWT_VALIDATION_ERROR';

    if (jwtError.name === 'TokenExpiredError') {
      message = 'JWT token has expired';
      code = 'JWT_EXPIRED';
    } else if (jwtError.name === 'JsonWebTokenError') {
      message = jwtError.message || 'Invalid JWT token';
      code = 'JWT_INVALID';
    } else if (jwtError.name === 'NotBeforeError') {
      message = 'JWT token not yet valid (nbf claim)';
      code = 'JWT_NOT_ACTIVE';
    } else {
      message = jwtError.message || message;
    }

    return this.createValidationError(message, code, {
      originalError: jwtError.name,
    });
  }

  /**
   * Extract error message from various error types
   *
   * @param error - Error object
   * @returns Human-readable error message
   */
  private extractErrorMessage(error: any): string {
    if (error.message) {
      return error.message;
    }

    if (typeof error === 'string') {
      return error;
    }

    return 'Unknown JWT validation error';
  }

  /**
   * Validate JWT validator configuration
   *
   * @param config - Configuration to validate
   * @returns Validated configuration with defaults
   * @throws Error if configuration is invalid
   */
  private validateConfig(config: JWTValidatorConfig): JWTValidatorConfig {
    // Apply defaults
    const validated: JWTValidatorConfig = {
      ...config,
      enableCaching: config.enableCaching ?? true,
      cacheTTL: config.cacheTTL ?? 5 * 60 * 1000, // 5 minutes
      clockTolerance: config.clockTolerance ?? 30, // 30 seconds
      requireIssuedAt: config.requireIssuedAt ?? true,
    };

    // Validation checks
    if (!validated.algorithm) {
      throw new Error('JWT algorithm is required');
    }

    if (!validated.issuer) {
      throw new Error('JWT issuer is required');
    }

    if (!validated.audience) {
      throw new Error('JWT audience is required');
    }

    if (!validated.secret && !validated.publicKey) {
      throw new Error('JWT secret or publicKey is required');
    }

    // Algorithm-specific validations
    const supportedAlgorithms = [
      'HS256',
      'HS384',
      'HS512',
      'RS256',
      'RS384',
      'RS512',
      'ES256',
      'ES384',
      'ES512',
    ];
    if (!supportedAlgorithms.includes(validated.algorithm)) {
      throw new Error(`Unsupported JWT algorithm: ${validated.algorithm}`);
    }

    // Symmetric algorithms require secret
    if (
      ['HS256', 'HS384', 'HS512'].includes(validated.algorithm) &&
      !validated.secret
    ) {
      throw new Error(`Algorithm ${validated.algorithm} requires a secret key`);
    }

    // Asymmetric algorithms require public key for verification
    if (
      ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'].includes(
        validated.algorithm
      ) &&
      !validated.publicKey
    ) {
      throw new Error(`Algorithm ${validated.algorithm} requires a public key`);
    }

    return validated;
  }

  // ============================================================================
  // PUBLIC UTILITY METHODS
  // ============================================================================

  /**
   * Get current cache size
   */
  public getCacheSize(): number {
    return this.cache.size;
  }

  /**
   * Clear validation cache
   */
  public clearCache(): void {
    this.cache.clear();
    console.log('🧹 JWT validation cache cleared');
  }

  /**
   * Get validator configuration (safe copy)
   */
  public getConfig(): Omit<JWTValidatorConfig, 'secret' | 'publicKey'> {
    const { secret, publicKey, ...safeConfig } = this.config;
    return safeConfig;
  }

  /**
   * Create a test JWT token (development only)
   *
   * @param payload - Token payload
   * @param expiresIn - Token expiration
   * @returns Signed JWT token
   */
  public createTestToken(
    payload: Partial<TokenPayload>,
    expiresIn = '1h'
  ): string {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Test token creation not allowed in production');
    }

    const basePayload = {
      iss: this.config.issuer,
      aud: this.config.audience,
      iat: Math.floor(Date.now() / 1000),
      sub: 'test-user',
      ...payload,
    };

    // Remove exp if using expiresIn to avoid conflicts
    const { exp, ...tokenPayload } = basePayload;

    return jwt.sign(tokenPayload, this.secret, {
      algorithm: this.config.algorithm as jwt.Algorithm,
      expiresIn,
    } as jwt.SignOptions);
  }
}
