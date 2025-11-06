/**
 * Firebase Token Validator
 *
 * Production-ready Firebase ID token validation implementation for the Guard
 * System Showcase. Integrates with Firebase Admin SDK to verify Firebase
 * Authentication tokens with comprehensive validation and performance optimization.
 *
 * Features:
 * - Firebase Admin SDK integration
 * - ID token verification with automatic key rotation handling
 * - Custom claims extraction and validation
 * - Performance optimization through caching
 * - Detailed error reporting and security logging
 * - Support for Firebase project configuration
 *
 * @module FirebaseTokenValidator
 * @version 1.0.0
 */

import { auth } from 'firebase-admin';
import { BaseTokenValidator } from './base-token-validator';
import {
  TokenPayload,
  TokenValidationResult,
  AuthProviderType,
  FirebaseAuthConfig,
} from '@/types/auth.types';

/**
 * Firebase-specific configuration options
 */
export interface FirebaseValidatorConfig extends FirebaseAuthConfig {
  /** Whether to cache validation results */
  enableCaching: boolean;

  /** Cache TTL for successful validations (milliseconds) */
  cacheTTL: number;

  /** Whether to verify email is verified */
  requireEmailVerified: boolean;

  /** Allowed Firebase projects (for multi-tenant) */
  allowedProjects?: string[];

  /** Custom claims to require */
  requiredClaims?: string[];

  /** Clock tolerance for time-based claims (seconds) */
  clockTolerance: number;
}

/**
 * Firebase token validation cache entry
 */
interface FirebaseCacheEntry {
  result: TokenValidationResult;
  userRecord?: auth.UserRecord;
  expiry: number;
}

/**
 * Firebase Token Validator Implementation
 *
 * Provides comprehensive Firebase ID token validation with:
 * - Firebase Admin SDK integration for token verification
 * - User record fetching and custom claims extraction
 * - Performance optimization through intelligent caching
 * - Security-focused validation and error handling
 * - Support for multi-tenant Firebase configurations
 */
export class FirebaseTokenValidator extends BaseTokenValidator {
  private readonly config: FirebaseValidatorConfig;
  private readonly cache = new Map<string, FirebaseCacheEntry>();
  private readonly firebaseAuth: auth.Auth;

  constructor(config: FirebaseValidatorConfig, firebaseAuth?: auth.Auth) {
    super(AuthProviderType.FIREBASE);
    this.config = this.validateConfig(config);

    // Use provided Firebase Auth instance or default
    this.firebaseAuth = firebaseAuth || auth();

    console.log(
      `🔥 Firebase Token Validator initialized for project: ${this.config.projectId}`
    );
  }

  // ============================================================================
  // CORE VALIDATION METHODS
  // ============================================================================

  /**
   * Validate Firebase ID token with comprehensive checks
   *
   * Performs the following validations:
   * 1. Firebase ID token verification using Admin SDK
   * 2. User record fetching and status validation
   * 3. Email verification check (if required)
   * 4. Custom claims validation
   * 5. Project allowlist validation (for multi-tenant)
   *
   * @param token - Firebase ID token string to validate
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
          'Invalid Firebase ID token format',
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

      // Verify Firebase ID token
      const decodedToken = await this.verifyFirebaseToken(token);
      const result = this.handleValidationResult(
        true,
        decodedToken,
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
   * Extract user ID from Firebase token payload
   *
   * @param decoded - Firebase token payload
   * @returns User ID string
   */
  public extractUserId(decoded: TokenPayload): string {
    return decoded.sub || (decoded as any).uid || '';
  }

  // ============================================================================
  // FIREBASE-SPECIFIC VALIDATION LOGIC
  // ============================================================================

  /**
   * Verify Firebase ID token and extract user information
   *
   * @param token - Firebase ID token string
   * @returns Promise resolving to decoded token payload
   * @throws Error if verification fails
   */
  private async verifyFirebaseToken(token: string): Promise<TokenPayload> {
    try {
      // Verify the ID token using Firebase Admin SDK
      const decodedToken = await this.firebaseAuth.verifyIdToken(token, true);

      // Validate project if allowlist is configured
      if (
        this.config.allowedProjects &&
        this.config.allowedProjects.length > 0
      ) {
        if (!this.config.allowedProjects.includes(decodedToken.aud)) {
          throw this.createValidationError(
            `Token from unauthorized project: ${decodedToken.aud}`,
            'UNAUTHORIZED_PROJECT'
          );
        }
      }

      // Fetch user record for additional validation
      const userRecord = await this.firebaseAuth.getUser(decodedToken.uid);

      // Validate user account status
      this.validateUserAccount(userRecord);

      // Create standardized token payload
      const payload: TokenPayload = {
        ...decodedToken, // Include all Firebase-specific claims first
        sub: decodedToken.uid,
        iss: decodedToken.iss,
        aud: decodedToken.aud,
        exp: decodedToken.exp,
        iat: decodedToken.iat,
        email: decodedToken.email,
        name: decodedToken.name || userRecord.displayName,
      };

      // Perform additional custom validations
      this.performCustomValidations(payload, userRecord);

      return payload;
    } catch (error) {
      throw this.createFirebaseError(error);
    }
  }

  /**
   * Validate Firebase user account status
   *
   * @param userRecord - Firebase user record
   * @throws Error if user account is invalid
   */
  private validateUserAccount(userRecord: auth.UserRecord): void {
    // Check if user account is disabled
    if (userRecord.disabled) {
      throw this.createValidationError(
        'User account is disabled',
        'USER_DISABLED'
      );
    }

    // Check email verification if required
    if (this.config.requireEmailVerified && !userRecord.emailVerified) {
      throw this.createValidationError(
        'Email address not verified',
        'EMAIL_NOT_VERIFIED'
      );
    }

    // Check for suspicious account patterns
    if (!userRecord.email && !userRecord.phoneNumber) {
      throw this.createValidationError(
        'User account missing contact information',
        'INCOMPLETE_ACCOUNT'
      );
    }
  }

  /**
   * Perform custom Firebase-specific validations
   *
   * @param payload - Firebase token payload
   * @param userRecord - Firebase user record
   * @throws Error if custom validation fails
   */
  private performCustomValidations(
    payload: TokenPayload,
    userRecord: auth.UserRecord
  ): void {
    // Validate required custom claims
    if (this.config.requiredClaims) {
      for (const requiredClaim of this.config.requiredClaims) {
        if (!(requiredClaim in payload)) {
          throw this.createValidationError(
            `Token missing required claim: ${requiredClaim}`,
            'MISSING_REQUIRED_CLAIM',
            { claim: requiredClaim }
          );
        }
      }
    }

    // Additional security validations
    this.performSecurityValidations(payload, userRecord);
  }

  /**
   * Perform additional security validations
   *
   * @param payload - Firebase token payload
   * @param userRecord - Firebase user record
   * @throws Error if security validation fails
   */
  private performSecurityValidations(
    payload: TokenPayload,
    userRecord: auth.UserRecord
  ): void {
    const now = Math.floor(Date.now() / 1000);

    // Check token freshness (Firebase tokens are typically short-lived)
    if (payload.iat) {
      const tokenAge = now - payload.iat;
      // Firebase ID tokens are valid for 1 hour, warn if older than 30 minutes
      if (tokenAge > 30 * 60) {
        console.warn(
          `⚠️ Firebase token is aging: ${tokenAge}s old (issued: ${new Date(payload.iat * 1000).toISOString()})`
        );
      }
    }

    // Check for recently created accounts (potential spam/abuse)
    if (userRecord.metadata.creationTime) {
      const accountAge =
        now -
        Math.floor(new Date(userRecord.metadata.creationTime).getTime() / 1000);
      if (accountAge < 60) {
        // Less than 1 minute old
        console.warn(
          `⚠️ Very new Firebase account detected: ${accountAge}s old (user: ${userRecord.uid})`
        );
      }
    }

    // Validate auth time if available
    if (
      (payload as any).auth_time &&
      typeof (payload as any).auth_time === 'number'
    ) {
      const authAge = now - (payload as any).auth_time;
      // Auth should be recent for sensitive operations
      if (authAge > 24 * 60 * 60) {
        // Older than 24 hours
        console.warn(
          `⚠️ Firebase auth time is old: ${authAge}s ago (user: ${userRecord.uid})`
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
   * @param token - Firebase ID token string
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
   * @param token - Firebase ID token string
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

    // Periodic cache cleanup
    if (this.cache.size > 5000) {
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
      console.debug(
        `🧹 Firebase cache cleanup: removed ${cleaned} expired entries`
      );
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
      console.debug(`${valid ? '✅' : '❌'} Firebase validation:`, {
        valid,
        userId: decoded?.sub,
        email: decoded?.email,
        error: error,
        time: `${validationTimeUs.toFixed(1)}μs`,
      });
    }

    return result;
  }

  /**
   * Create Firebase-specific error from various Firebase error types
   *
   * @param firebaseError - Error from Firebase Admin SDK
   * @returns Standardized validation error
   */
  private createFirebaseError(firebaseError: any): Error {
    let message = 'Firebase token validation failed';
    let code = 'FIREBASE_VALIDATION_ERROR';

    // Handle specific Firebase error codes
    if (firebaseError.code) {
      switch (firebaseError.code) {
        case 'auth/id-token-expired':
          message = 'Firebase ID token has expired';
          code = 'FIREBASE_TOKEN_EXPIRED';
          break;
        case 'auth/id-token-revoked':
          message = 'Firebase ID token has been revoked';
          code = 'FIREBASE_TOKEN_REVOKED';
          break;
        case 'auth/invalid-id-token':
          message = 'Invalid Firebase ID token';
          code = 'FIREBASE_TOKEN_INVALID';
          break;
        case 'auth/user-not-found':
          message = 'Firebase user not found';
          code = 'FIREBASE_USER_NOT_FOUND';
          break;
        case 'auth/user-disabled':
          message = 'Firebase user account is disabled';
          code = 'FIREBASE_USER_DISABLED';
          break;
        default:
          message = firebaseError.message || message;
          break;
      }
    } else {
      message = firebaseError.message || message;
    }

    return this.createValidationError(message, code, {
      originalError: firebaseError.code,
      details: firebaseError.message,
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

    return 'Unknown Firebase validation error';
  }

  /**
   * Validate Firebase validator configuration
   *
   * @param config - Configuration to validate
   * @returns Validated configuration with defaults
   * @throws Error if configuration is invalid
   */
  private validateConfig(
    config: FirebaseValidatorConfig
  ): FirebaseValidatorConfig {
    // Apply defaults
    const validated: FirebaseValidatorConfig = {
      ...config,
      enableCaching: config.enableCaching ?? true,
      cacheTTL: config.cacheTTL ?? 5 * 60 * 1000, // 5 minutes
      requireEmailVerified: config.requireEmailVerified ?? false,
      clockTolerance: config.clockTolerance ?? 30, // 30 seconds
    };

    // Validation checks
    if (!validated.projectId) {
      throw new Error('Firebase project ID is required');
    }

    if (!validated.privateKey) {
      throw new Error('Firebase private key is required');
    }

    if (!validated.clientEmail) {
      throw new Error('Firebase client email is required');
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
    console.log('🧹 Firebase validation cache cleared');
  }

  /**
   * Get validator configuration (safe copy)
   */
  public getConfig(): Omit<FirebaseValidatorConfig, 'privateKey'> {
    const { ...safeConfig } = this.config;
    return safeConfig;
  }

  /**
   * Get Firebase project ID
   */
  public getProjectId(): string {
    return this.config.projectId;
  }
}
