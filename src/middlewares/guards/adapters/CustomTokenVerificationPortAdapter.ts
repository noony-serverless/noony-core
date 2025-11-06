/**
 * CustomTokenVerificationPort Adapter
 *
 * Bridges the CustomTokenVerificationPort interface from AuthenticationMiddleware
 * to the RouteGuards TokenValidator interface, enabling code reuse and unified
 * token validation across the entire Noony Framework.
 *
 * Key Features:
 * - Seamless integration between authentication systems
 * - Maintains type safety through generics
 * - Supports any token validation implementation (JWT, OAuth, API keys, etc.)
 * - Preserves all existing RouteGuards functionality
 * - Zero-overhead abstraction with full performance
 *
 * Benefits:
 * - One authentication interface to implement and maintain
 * - Consistent patterns across AuthenticationMiddleware and RouteGuards
 * - Backward compatibility with existing RouteGuards implementations
 * - Simplified setup for authentication workflows
 *
 * @example
 * Bridge a JWT verification port to RouteGuards:
 * ```typescript
 * import { CustomTokenVerificationPort } from '@/middlewares/authenticationMiddleware';
 * import { CustomTokenVerificationPortAdapter } from '@/middlewares/guards/adapters';
 *
 * // Define your user type
 * interface User {
 *   id: string;
 *   email: string;
 *   roles: string[];
 *   sub: string;  // JWT subject
 *   exp: number;  // JWT expiration
 *   iat: number;  // Issued at
 * }
 *
 * // Implement token verification once
 * const jwtVerifier: CustomTokenVerificationPort<User> = {
 *   async verifyToken(token: string): Promise<User> {
 *     const payload = jwt.verify(token, process.env.JWT_SECRET!) as any;
 *     return {
 *       id: payload.sub,
 *       email: payload.email,
 *       roles: payload.roles || [],
 *       sub: payload.sub,
 *       exp: payload.exp,
 *       iat: payload.iat
 *     };
 *   }
 * };
 *
 * // Create adapter for RouteGuards
 * const tokenValidator = new CustomTokenVerificationPortAdapter(
 *   jwtVerifier,
 *   {
 *     userIdExtractor: (user: User) => user.id,
 *     expirationExtractor: (user: User) => user.exp
 *   }
 * );
 *
 * // Use with RouteGuards
 * await RouteGuards.configure(
 *   GuardSetup.production(),
 *   userPermissionSource,
 *   tokenValidator, // Works seamlessly!
 *   authConfig
 * );
 * ```
 *
 * @example
 * API key verification with custom user structure:
 * ```typescript
 * interface APIKeyUser {
 *   keyId: string;
 *   permissions: string[];
 *   organization: string;
 *   expiresAt: number;
 *   isActive: boolean;
 * }
 *
 * const apiKeyVerifier: CustomTokenVerificationPort<APIKeyUser> = {
 *   async verifyToken(token: string): Promise<APIKeyUser> {
 *     const keyData = await validateAPIKey(token);
 *     if (!keyData || !keyData.isActive) {
 *       throw new Error('Invalid or inactive API key');
 *     }
 *     return keyData;
 *   }
 * };
 *
 * // Adapter with custom extractors
 * const apiTokenValidator = new CustomTokenVerificationPortAdapter(
 *   apiKeyVerifier,
 *   {
 *     userIdExtractor: (user: APIKeyUser) => user.keyId,
 *     expirationExtractor: (user: APIKeyUser) => user.expiresAt,
 *     additionalValidation: (user: APIKeyUser) => user.isActive
 *   }
 * );
 *
 * // Seamlessly works with RouteGuards
 * await RouteGuards.configure(
 *   GuardSetup.production(),
 *   userPermissionSource,
 *   apiTokenValidator,
 *   authConfig
 * );
 * ```
 *
 * @example
 * OAuth token verification:
 * ```typescript
 * interface OAuthUser {
 *   sub: string;        // OAuth subject
 *   email: string;
 *   scope: string[];    // OAuth scopes
 *   exp: number;
 *   client_id: string;
 * }
 *
 * const oauthVerifier: CustomTokenVerificationPort<OAuthUser> = {
 *   async verifyToken(token: string): Promise<OAuthUser> {
 *     // Validate with OAuth provider
 *     const response = await fetch(`${OAUTH_INTROSPECT_URL}`, {
 *       method: 'POST',
 *       headers: { 'Authorization': `Bearer ${token}` }
 *     });
 *
 *     const tokenInfo = await response.json();
 *     if (!tokenInfo.active) {
 *       throw new Error('Token is not active');
 *     }
 *
 *     return tokenInfo as OAuthUser;
 *   }
 * };
 *
 * const oauthTokenValidator = new CustomTokenVerificationPortAdapter(
 *   oauthVerifier,
 *   {
 *     userIdExtractor: (user: OAuthUser) => user.sub,
 *     expirationExtractor: (user: OAuthUser) => user.exp
 *   }
 * );
 * ```
 *
 * @author Noony Framework Team
 * @version 1.0.0
 */

import { CustomTokenVerificationPort } from '../../authenticationMiddleware';
import { TokenValidator } from '../guards/FastAuthGuard';

/**
 * Configuration options for the CustomTokenVerificationPort adapter.
 * Provides flexible configuration for extracting required data from
 * different user object structures.
 */
export interface AdapterConfig<T> {
  /**
   * Extract user ID from the verified user object.
   * This ID will be used for permission lookups and caching.
   */
  userIdExtractor: (user: T) => string;

  /**
   * Extract token expiration timestamp from the user object.
   * Should return Unix timestamp (seconds since epoch).
   *
   * @param user - Verified user object
   * @returns Unix timestamp or undefined if no expiration
   */
  expirationExtractor?: (user: T) => number | undefined;

  /**
   * Optional additional validation after token verification.
   * Allows custom business logic validation on the verified user.
   *
   * @param user - Verified user object
   * @returns true if user passes additional validation
   */
  additionalValidation?: (user: T) => boolean | Promise<boolean>;

  /**
   * Custom error message for token validation failures.
   * If not provided, uses the original error from the verification port.
   */
  errorMessage?: string;
}

/**
 * Adapter class that bridges CustomTokenVerificationPort to TokenValidator.
 * Enables seamless integration between AuthenticationMiddleware and RouteGuards
 * while maintaining full type safety and performance.
 *
 * @template T - The user type returned by the CustomTokenVerificationPort
 */
export class CustomTokenVerificationPortAdapter<T> implements TokenValidator {
  private readonly verificationPort: CustomTokenVerificationPort<T>;
  private readonly config: AdapterConfig<T>;

  constructor(
    verificationPort: CustomTokenVerificationPort<T>,
    config: AdapterConfig<T>
  ) {
    this.verificationPort = verificationPort;
    this.config = config;
  }

  /**
   * Validate and decode token using the wrapped CustomTokenVerificationPort.
   *
   * @param token - JWT token string to validate
   * @returns Validation result with decoded user data
   */
  async validateToken(token: string): Promise<{
    valid: boolean;
    decoded?: T;
    error?: string;
  }> {
    try {
      // Use the wrapped verification port to verify the token
      const user = await this.verificationPort.verifyToken(token);

      // Run additional validation if configured
      if (this.config.additionalValidation) {
        const additionalValid = await this.config.additionalValidation(user);
        if (!additionalValid) {
          return {
            valid: false,
            error: this.config.errorMessage || 'Additional validation failed',
          };
        }
      }

      return {
        valid: true,
        decoded: user,
      };
    } catch (error) {
      return {
        valid: false,
        error:
          this.config.errorMessage ||
          (error instanceof Error ? error.message : 'Token validation failed'),
      };
    }
  }

  /**
   * Extract user ID from the decoded token/user data.
   * Uses the configured userIdExtractor function.
   *
   * @param decoded - Decoded user data from validateToken
   * @returns User ID string
   */
  extractUserId(decoded: T): string {
    return this.config.userIdExtractor(decoded);
  }

  /**
   * Check if the token is expired based on the decoded data.
   * Uses the configured expirationExtractor if available.
   *
   * @param decoded - Decoded user data from validateToken
   * @returns true if token is expired, false otherwise
   */
  isTokenExpired(decoded: T): boolean {
    if (!this.config.expirationExtractor) {
      // If no expiration extractor is configured, assume token is valid
      return false;
    }

    const expirationTime = this.config.expirationExtractor(decoded);
    if (!expirationTime) {
      // If no expiration time is available, assume token is valid
      return false;
    }

    // Compare with current time (convert to seconds)
    const currentTime = Math.floor(Date.now() / 1000);
    return expirationTime <= currentTime;
  }
}

/**
 * Helper factory functions for common token verification scenarios.
 * Provides pre-configured adapters for standard authentication patterns.
 */
export class TokenVerificationAdapterFactory {
  /**
   * Create adapter for standard JWT tokens with common claims.
   * Assumes the user object has 'sub' for user ID and 'exp' for expiration.
   *
   * @param verificationPort - JWT token verification port
   * @returns Configured adapter for JWT tokens
   */
  static forJWT<T extends { sub: string; exp?: number }>(
    verificationPort: CustomTokenVerificationPort<T>
  ): CustomTokenVerificationPortAdapter<T> {
    return new CustomTokenVerificationPortAdapter(verificationPort, {
      userIdExtractor: (user: T) => user.sub,
      expirationExtractor: (user: T) => user.exp,
    });
  }

  /**
   * Create adapter for API key tokens with custom ID and expiration fields.
   *
   * @param verificationPort - API key verification port
   * @param userIdField - Field name for user/key ID (e.g., 'keyId', 'apiKeyId')
   * @param expirationField - Optional field name for expiration (e.g., 'expiresAt', 'exp')
   * @returns Configured adapter for API key tokens
   */
  static forAPIKey<T extends Record<string, any>>(
    verificationPort: CustomTokenVerificationPort<T>,
    userIdField: keyof T,
    expirationField?: keyof T
  ): CustomTokenVerificationPortAdapter<T> {
    return new CustomTokenVerificationPortAdapter(verificationPort, {
      userIdExtractor: (user: T) => String(user[userIdField]),
      expirationExtractor: expirationField
        ? (user: T) => user[expirationField] as number
        : undefined,
    });
  }

  /**
   * Create adapter for OAuth tokens with standard OAuth claims.
   *
   * @param verificationPort - OAuth token verification port
   * @param additionalScopes - Optional required OAuth scopes
   * @returns Configured adapter for OAuth tokens
   */
  static forOAuth<T extends { sub: string; exp?: number; scope?: string[] }>(
    verificationPort: CustomTokenVerificationPort<T>,
    additionalScopes?: string[]
  ): CustomTokenVerificationPortAdapter<T> {
    return new CustomTokenVerificationPortAdapter(verificationPort, {
      userIdExtractor: (user: T) => user.sub,
      expirationExtractor: (user: T) => user.exp,
      additionalValidation: additionalScopes
        ? (user: T) => {
            if (!user.scope || !Array.isArray(user.scope)) {
              return false;
            }
            return additionalScopes.every((requiredScope) =>
              user.scope!.includes(requiredScope)
            );
          }
        : undefined,
    });
  }

  /**
   * Create adapter with custom configuration.
   * Use this for non-standard token structures or complex validation logic.
   *
   * @param verificationPort - Token verification port
   * @param config - Custom adapter configuration
   * @returns Configured adapter with custom settings
   */
  static custom<T>(
    verificationPort: CustomTokenVerificationPort<T>,
    config: AdapterConfig<T>
  ): CustomTokenVerificationPortAdapter<T> {
    return new CustomTokenVerificationPortAdapter(verificationPort, config);
  }
}
