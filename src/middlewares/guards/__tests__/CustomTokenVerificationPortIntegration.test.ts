/**
 * CustomTokenVerificationPort Integration Tests
 *
 * Tests the integration between CustomTokenVerificationPort from AuthenticationMiddleware
 * and the RouteGuards system. Verifies that token verification ports can be seamlessly
 * used across both authentication systems.
 */

import { CustomTokenVerificationPort } from '../../authenticationMiddleware';
import {
  CustomTokenVerificationPortAdapter,
  TokenVerificationAdapterFactory,
  AdapterConfig,
} from '../adapters/CustomTokenVerificationPortAdapter';
import { TokenValidator } from '../guards/FastAuthGuard';

describe('CustomTokenVerificationPort Integration', () => {
  describe('CustomTokenVerificationPortAdapter', () => {
    interface TestUser {
      sub: string;
      email: string;
      roles: string[];
      exp: number;
      iat: number;
    }

    const mockUser: TestUser = {
      sub: 'user-123',
      email: 'test@example.com',
      roles: ['user', 'admin'],
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
      iat: Math.floor(Date.now() / 1000),
    };

    describe('validateToken', () => {
      it('should return valid result when token verification succeeds', async () => {
        // Arrange
        const mockTokenVerificationPort: CustomTokenVerificationPort<TestUser> = {
          async verifyToken(_token: string): Promise<TestUser> {
            return mockUser;
          }
        };

        const adapterConfig: AdapterConfig<TestUser> = {
          userIdExtractor: (user: TestUser) => user.sub,
          expirationExtractor: (user: TestUser) => user.exp,
        };

        const adapter = new CustomTokenVerificationPortAdapter(
          mockTokenVerificationPort,
          adapterConfig
        );

        // Act
        const result = await adapter.validateToken('valid-token');

        // Assert
        expect(result).toEqual({
          valid: true,
          decoded: mockUser,
        });
      });

      it('should return invalid result when token verification fails', async () => {
        // Arrange
        const mockTokenVerificationPort: CustomTokenVerificationPort<TestUser> = {
          async verifyToken(_token: string): Promise<TestUser> {
            throw new Error('Invalid token');
          }
        };

        const adapterConfig: AdapterConfig<TestUser> = {
          userIdExtractor: (user: TestUser) => user.sub,
          expirationExtractor: (user: TestUser) => user.exp,
        };

        const adapter = new CustomTokenVerificationPortAdapter(
          mockTokenVerificationPort,
          adapterConfig
        );

        // Act
        const result = await adapter.validateToken('invalid-token');

        // Assert
        expect(result).toEqual({
          valid: false,
          error: 'Invalid token',
        });
      });

      it('should return custom error message when configured', async () => {
        // Arrange
        const mockTokenVerificationPort: CustomTokenVerificationPort<TestUser> = {
          async verifyToken(_token: string): Promise<TestUser> {
            throw new Error('Invalid token');
          }
        };

        const customAdapter = new CustomTokenVerificationPortAdapter(
          mockTokenVerificationPort,
          {
            userIdExtractor: (user: TestUser) => user.sub,
            expirationExtractor: (user: TestUser) => user.exp,
            errorMessage: 'Custom authentication failed',
          }
        );

        // Act
        const result = await customAdapter.validateToken('invalid-token');

        // Assert
        expect(result).toEqual({
          valid: false,
          error: 'Custom authentication failed',
        });
      });

      it('should fail additional validation when configured', async () => {
        // Arrange
        const mockTokenVerificationPort: CustomTokenVerificationPort<TestUser> = {
          async verifyToken(_token: string): Promise<TestUser> {
            return mockUser;
          }
        };

        const customAdapter = new CustomTokenVerificationPortAdapter(
          mockTokenVerificationPort,
          {
            userIdExtractor: (user: TestUser) => user.sub,
            expirationExtractor: (user: TestUser) => user.exp,
            additionalValidation: (_user: TestUser) => false,
          }
        );

        // Act
        const result = await customAdapter.validateToken('valid-token');

        // Assert
        expect(result).toEqual({
          valid: false,
          error: 'Additional validation failed',
        });
      });

      it('should pass additional validation when configured correctly', async () => {
        // Arrange
        const mockTokenVerificationPort: CustomTokenVerificationPort<TestUser> = {
          async verifyToken(_token: string): Promise<TestUser> {
            return mockUser;
          }
        };

        const customAdapter = new CustomTokenVerificationPortAdapter(
          mockTokenVerificationPort,
          {
            userIdExtractor: (user: TestUser) => user.sub,
            expirationExtractor: (user: TestUser) => user.exp,
            additionalValidation: (_user: TestUser) => true,
          }
        );

        // Act
        const result = await customAdapter.validateToken('valid-token');

        // Assert
        expect(result).toEqual({
          valid: true,
          decoded: mockUser,
        });
      });
    });

    describe('extractUserId', () => {
      it('should extract user ID using configured extractor', () => {
        // Arrange
        const mockTokenVerificationPort: CustomTokenVerificationPort<TestUser> = {
          async verifyToken(_token: string): Promise<TestUser> {
            return mockUser;
          }
        };

        const adapterConfig: AdapterConfig<TestUser> = {
          userIdExtractor: (user: TestUser) => user.sub,
          expirationExtractor: (user: TestUser) => user.exp,
        };

        const adapter = new CustomTokenVerificationPortAdapter(
          mockTokenVerificationPort,
          adapterConfig
        );

        // Act
        const userId = adapter.extractUserId(mockUser);

        // Assert
        expect(userId).toBe('user-123');
      });
    });

    describe('isTokenExpired', () => {
      it('should return false for non-expired token', () => {
        // Arrange
        const mockTokenVerificationPort: CustomTokenVerificationPort<TestUser> = {
          async verifyToken(_token: string): Promise<TestUser> {
            return mockUser;
          }
        };

        const adapterConfig: AdapterConfig<TestUser> = {
          userIdExtractor: (user: TestUser) => user.sub,
          expirationExtractor: (user: TestUser) => user.exp,
        };

        const adapter = new CustomTokenVerificationPortAdapter(
          mockTokenVerificationPort,
          adapterConfig
        );

        // Act
        const isExpired = adapter.isTokenExpired(mockUser);

        // Assert
        expect(isExpired).toBe(false);
      });

      it('should return true for expired token', () => {
        // Arrange
        const mockTokenVerificationPort: CustomTokenVerificationPort<TestUser> = {
          async verifyToken(_token: string): Promise<TestUser> {
            return mockUser;
          }
        };

        const adapterConfig: AdapterConfig<TestUser> = {
          userIdExtractor: (user: TestUser) => user.sub,
          expirationExtractor: (user: TestUser) => user.exp,
        };

        const adapter = new CustomTokenVerificationPortAdapter(
          mockTokenVerificationPort,
          adapterConfig
        );

        const expiredUser = {
          ...mockUser,
          exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
        };

        // Act
        const isExpired = adapter.isTokenExpired(expiredUser);

        // Assert
        expect(isExpired).toBe(true);
      });

      it('should return false when no expiration extractor is configured', () => {
        // Arrange
        const mockTokenVerificationPort: CustomTokenVerificationPort<TestUser> = {
          async verifyToken(_token: string): Promise<TestUser> {
            return mockUser;
          }
        };

        const noExpirationAdapter = new CustomTokenVerificationPortAdapter(
          mockTokenVerificationPort,
          {
            userIdExtractor: (user: TestUser) => user.sub,
            // No expirationExtractor
          }
        );

        // Act
        const isExpired = noExpirationAdapter.isTokenExpired(mockUser);

        // Assert
        expect(isExpired).toBe(false);
      });

      it('should return false when expiration time is not available', () => {
        // Arrange
        const mockTokenVerificationPort: CustomTokenVerificationPort<TestUser> = {
          async verifyToken(_token: string): Promise<TestUser> {
            return mockUser;
          }
        };

        const adapter = new CustomTokenVerificationPortAdapter(
          mockTokenVerificationPort,
          {
            userIdExtractor: (user: TestUser) => user.sub,
            expirationExtractor: () => undefined,
          }
        );

        // Act
        const isExpired = adapter.isTokenExpired(mockUser);

        // Assert
        expect(isExpired).toBe(false);
      });
    });
  });

  describe('TokenVerificationAdapterFactory', () => {
    describe('forJWT', () => {
      it('should create adapter with correct JWT configuration', async () => {
        // Arrange
        interface JWTUser {
          sub: string;
          exp: number;
          email: string;
        }

        const jwtUser: JWTUser = {
          sub: 'jwt-user-123',
          exp: Math.floor(Date.now() / 1000) + 3600,
          email: 'jwt@example.com',
        };

        const mockJWTPort: CustomTokenVerificationPort<JWTUser> = {
          async verifyToken(_token: string): Promise<JWTUser> {
            return jwtUser;
          }
        };

        // Act
        const adapter = TokenVerificationAdapterFactory.forJWT(mockJWTPort);

        // Assert
        expect(adapter).toBeInstanceOf(CustomTokenVerificationPortAdapter);

        // Test the adapter works correctly
        const result = await adapter.validateToken('jwt-token');
        expect(result.valid).toBe(true);
        expect(result.decoded).toEqual(jwtUser);

        const userId = adapter.extractUserId(jwtUser);
        expect(userId).toBe('jwt-user-123');

        const isExpired = adapter.isTokenExpired(jwtUser);
        expect(isExpired).toBe(false);
      });
    });

    describe('forAPIKey', () => {
      it('should create adapter with correct API key configuration', async () => {
        // Arrange
        interface APIKeyUser {
          keyId: string;
          permissions: string[];
          expiresAt: number;
        }

        const apiKeyUser: APIKeyUser = {
          keyId: 'api-key-123',
          permissions: ['read', 'write'],
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
        };

        const mockAPIKeyPort: CustomTokenVerificationPort<APIKeyUser> = {
          async verifyToken(_token: string): Promise<APIKeyUser> {
            return apiKeyUser;
          }
        };

        // Act
        const adapter = TokenVerificationAdapterFactory.forAPIKey(
          mockAPIKeyPort,
          'keyId',
          'expiresAt'
        );

        // Assert
        expect(adapter).toBeInstanceOf(CustomTokenVerificationPortAdapter);

        // Test the adapter works correctly
        const result = await adapter.validateToken('api-key-token');
        expect(result.valid).toBe(true);
        expect(result.decoded).toEqual(apiKeyUser);

        const userId = adapter.extractUserId(apiKeyUser);
        expect(userId).toBe('api-key-123');

        const isExpired = adapter.isTokenExpired(apiKeyUser);
        expect(isExpired).toBe(false);
      });
    });

    describe('forOAuth', () => {
      it('should create adapter with correct OAuth configuration', async () => {
        // Arrange
        interface OAuthUser {
          sub: string;
          exp: number;
          scope: string[];
        }

        const oauthUser: OAuthUser = {
          sub: 'oauth-user-123',
          exp: Math.floor(Date.now() / 1000) + 3600,
          scope: ['read:profile', 'write:data'],
        };

        const mockOAuthPort: CustomTokenVerificationPort<OAuthUser> = {
          async verifyToken(_token: string): Promise<OAuthUser> {
            return oauthUser;
          }
        };

        // Act
        const adapter = TokenVerificationAdapterFactory.forOAuth(
          mockOAuthPort,
          ['read:profile']
        );

        // Assert
        expect(adapter).toBeInstanceOf(CustomTokenVerificationPortAdapter);

        // Test the adapter works correctly
        const result = await adapter.validateToken('oauth-token');
        expect(result.valid).toBe(true);
        expect(result.decoded).toEqual(oauthUser);

        const userId = adapter.extractUserId(oauthUser);
        expect(userId).toBe('oauth-user-123');
      });

      it('should fail validation when required scope is missing', async () => {
        // Arrange
        interface OAuthUser {
          sub: string;
          exp: number;
          scope: string[];
        }

        const oauthUser: OAuthUser = {
          sub: 'oauth-user-123',
          exp: Math.floor(Date.now() / 1000) + 3600,
          scope: ['read:profile'], // Missing 'admin:access'
        };

        const mockOAuthPort: CustomTokenVerificationPort<OAuthUser> = {
          async verifyToken(_token: string): Promise<OAuthUser> {
            return oauthUser;
          }
        };

        // Act
        const adapter = TokenVerificationAdapterFactory.forOAuth(
          mockOAuthPort,
          ['admin:access'] // Required scope not present
        );

        const result = await adapter.validateToken('oauth-token');

        // Assert
        expect(result.valid).toBe(false);
      });
    });

    describe('custom', () => {
      it('should create adapter with custom configuration', async () => {
        // Arrange
        interface CustomUser {
          userId: string;
          tenantId: string;
          sessionExpiry: number;
          isVerified: boolean;
        }

        const customUser: CustomUser = {
          userId: 'custom-user-123',
          tenantId: 'tenant-456',
          sessionExpiry: Math.floor(Date.now() / 1000) + 3600,
          isVerified: true,
        };

        const mockCustomPort: CustomTokenVerificationPort<CustomUser> = {
          async verifyToken(_token: string): Promise<CustomUser> {
            return customUser;
          }
        };

        const customConfig: AdapterConfig<CustomUser> = {
          userIdExtractor: (user) => user.userId,
          expirationExtractor: (user) => user.sessionExpiry,
          additionalValidation: (user) => user.isVerified,
        };

        // Act
        const adapter = TokenVerificationAdapterFactory.custom(
          mockCustomPort,
          customConfig
        );

        // Assert
        expect(adapter).toBeInstanceOf(CustomTokenVerificationPortAdapter);

        // Test the adapter works correctly
        const result = await adapter.validateToken('custom-token');
        expect(result.valid).toBe(true);
        expect(result.decoded).toEqual(customUser);

        const userId = adapter.extractUserId(customUser);
        expect(userId).toBe('custom-user-123');
      });
    });
  });

  describe('Type Compatibility', () => {
    it('should implement TokenValidator interface correctly', () => {
      // Arrange
      interface TestUser {
        sub: string;
        exp: number;
      }

      const mockPort: CustomTokenVerificationPort<TestUser> = {
        async verifyToken(_token: string): Promise<TestUser> {
          return { sub: 'test', exp: Date.now() };
        }
      };

      // Act
      const adapter = new CustomTokenVerificationPortAdapter(mockPort, {
        userIdExtractor: (user) => user.sub,
        expirationExtractor: (user) => user.exp,
      });

      // Assert - This test passes if the types are compatible
      const tokenValidator: TokenValidator = adapter;
      expect(tokenValidator).toBeDefined();
      expect(typeof tokenValidator.validateToken).toBe('function');
      expect(typeof tokenValidator.extractUserId).toBe('function');
      expect(typeof tokenValidator.isTokenExpired).toBe('function');
    });
  });

  describe('Error Scenarios', () => {
    it('should handle async additional validation', async () => {
      // Arrange
      interface TestUser {
        sub: string;
        isActive: boolean;
      }

      const user: TestUser = {
        sub: 'user-123',
        isActive: true,
      };

      const mockPort: CustomTokenVerificationPort<TestUser> = {
        async verifyToken(_token: string): Promise<TestUser> {
          return user;
        }
      };

      const adapter = new CustomTokenVerificationPortAdapter(mockPort, {
        userIdExtractor: (user) => user.sub,
        additionalValidation: async (user) => Promise.resolve(user.isActive),
      });

      // Act
      const result = await adapter.validateToken('token');

      // Assert
      expect(result.valid).toBe(true);
    });

    it('should handle async additional validation failure', async () => {
      // Arrange
      interface TestUser {
        sub: string;
        isActive: boolean;
      }

      const user: TestUser = {
        sub: 'user-123',
        isActive: false,
      };

      const mockPort: CustomTokenVerificationPort<TestUser> = {
        async verifyToken(_token: string): Promise<TestUser> {
          return user;
        }
      };

      const adapter = new CustomTokenVerificationPortAdapter(mockPort, {
        userIdExtractor: (user) => user.sub,
        additionalValidation: async (user) => Promise.resolve(user.isActive),
      });

      // Act
      const result = await adapter.validateToken('token');

      // Assert
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Additional validation failed');
    });
  });
});