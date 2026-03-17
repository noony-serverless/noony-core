# How to Build a Reusable Token Validator

The `TokenValidatorFactory` adds enterprise-grade capabilities — multi-provider failover, circuit breakers, health monitoring — while exposing the same `CustomTokenVerificationPort<T>` interface that `AuthenticationMiddleware` already expects. This means the handler code does not change; you swap the verifier implementation without touching any business logic.

## Primary Workflow: Create, Wrap, Reuse

Create the factory once at module load time, wrap it in a class that implements `CustomTokenVerificationPort<T>`, export a single `AuthenticationMiddleware` instance, and import that instance in every handler that needs authentication.

### Step 1: Create the factory and verifier

```typescript
// src/auth/auth.ts
import { TokenValidatorFactory, ValidatorFactoryConfig } from '@/auth/token-validator-factory';
import { CustomTokenVerificationPort, AuthenticationMiddleware } from '@/middlewares/authenticationMiddleware';
import { AuthProviderType } from '@/types/auth.types';

interface User {
  id: string;
  email: string;
  name: string;
  roles: string[];
  sub: string;
  exp: number;
  iat: number;
}

// Create the factory once — not per request, not per handler
const factory = new TokenValidatorFactory({
  primaryProvider: AuthProviderType.JWT,
  providers: {
    [AuthProviderType.JWT]: {
      secret: process.env.JWT_SECRET!,
      issuer: process.env.JWT_ISSUER || 'my-app',
      audience: process.env.JWT_AUDIENCE || 'my-api',
    },
  },
  settings: {
    enableFailover: false,
    maxFailoverAttempts: 1,
    circuitBreakerThreshold: 5,
    circuitBreakerResetTimeout: 60000,
    enableHealthMonitoring: false,
    healthCheckInterval: 30000,
  },
});

class JWTVerifier implements CustomTokenVerificationPort<User> {
  async verifyToken(token: string): Promise<User> {
    const result = await factory.validateToken(token);

    if (!result.valid || !result.decoded) {
      throw new Error(result.error || 'Token validation failed');
    }

    return {
      id: result.decoded.sub || '',
      email: result.decoded.email || '',
      name: result.decoded.name || '',
      roles: result.decoded.roles || [],
      sub: result.decoded.sub || '',
      exp: result.decoded.exp || 0,
      iat: result.decoded.iat || 0,
    };
  }
}

// Export one instance — import this in handlers, never construct another
export const authMiddleware = new AuthenticationMiddleware(new JWTVerifier());
```

Don't instantiate validators per request. The factory connects to external services and allocates connection pools; constructing it inside a request handler causes cold-start latency on every call and exhausts connection limits under load.

### Step 2: Import the shared middleware in handlers

```typescript
// src/handlers/handlers.ts
import { Handler } from '@/core/handler';
import { authMiddleware } from './auth';

const userProfileHandler = new Handler()
  .use(authMiddleware)
  .handle(async (request, context) => {
    const user = context.user as User;
    return { success: true, data: await getUserProfile(user.id) };
  });

const ordersHandler = new Handler()
  .use(authMiddleware)
  .handle(async (request, context) => {
    const user = context.user as User;
    return { success: true, data: await getUserOrders(user.id) };
  });

const settingsHandler = new Handler()
  .use(authMiddleware)
  .handle(async (request, context) => {
    const user = context.user as User;
    return { success: true, data: await getUserSettings(user.id) };
  });
```

## If You Need Multi-Provider Failover

Enable `enableFailover` and add `fallbackProviders`. The factory tries the primary provider first; if it throws or opens the circuit breaker, it falls back through the list automatically.

```typescript
// src/auth/advanced-auth.ts
const advancedFactory = new TokenValidatorFactory({
  primaryProvider: AuthProviderType.JWT,
  fallbackProviders: [AuthProviderType.FIREBASE],
  providers: {
    [AuthProviderType.JWT]: {
      secret: process.env.JWT_SECRET!,
      issuer: 'my-app',
      audience: 'my-api',
      algorithms: ['HS256', 'RS256'],
    },
    [AuthProviderType.FIREBASE]: {
      projectId: process.env.FIREBASE_PROJECT_ID!,
      audience: 'my-firebase-app',
    },
  },
  settings: {
    enableFailover: true,
    maxFailoverAttempts: 3,
    circuitBreakerThreshold: 5,
    circuitBreakerResetTimeout: 60000,
    enableHealthMonitoring: true,
    healthCheckInterval: 30000,
  },
});

class AdvancedJWTVerifier implements CustomTokenVerificationPort<User> {
  async verifyToken(token: string): Promise<User> {
    const result = await advancedFactory.validateToken(token);

    if (!result.valid || !result.decoded) {
      throw new Error(result.error || 'Token validation failed');
    }

    return {
      id: result.decoded.sub || '',
      email: result.decoded.email || '',
      name: result.decoded.name || '',
      roles: result.decoded.roles || [],
      sub: result.decoded.sub || '',
      exp: result.decoded.exp || 0,
      iat: result.decoded.iat || 0,
    };
  }
}

export const advancedAuthMiddleware = new AuthenticationMiddleware(
  new AdvancedJWTVerifier(),
  {
    maxTokenAge: 3600,
    clockTolerance: 60,
    requiredClaims: {
      issuer: 'my-app',
      audience: ['my-api', 'my-firebase-app'],
    },
  }
);
```

## If You Need Social Auth (Google/Facebook)

Implement separate validator classes for each social provider and route to them based on token shape. The `SocialAuthVerifier` wraps all providers behind the single `CustomTokenVerificationPort<T>` interface.

```typescript
// src/auth/social-auth.ts
import { OAuth2Client } from 'google-auth-library';
import axios from 'axios';

interface SocialUser extends User {
  provider: 'google' | 'facebook' | 'jwt';
  providerId: string;
  picture?: string;
  verified_email?: boolean;
}

class GoogleTokenValidator {
  private client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID!);

  async validateToken(token: string) {
    const ticket = await this.client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID!,
    });
    const payload = ticket.getPayload();
    if (!payload) return { valid: false, error: 'Invalid Google token payload' };
    return { valid: true, decoded: { ...payload, provider: 'google', providerId: payload.sub } };
  }
}

class SocialAuthVerifier implements CustomTokenVerificationPort<SocialUser> {
  private googleValidator = new GoogleTokenValidator();

  async verifyToken(token: string): Promise<SocialUser> {
    const tokenType = this.detectTokenType(token);
    let result: any;

    if (tokenType === 'google') {
      result = await this.googleValidator.validateToken(token);
    } else {
      result = await factory.validateToken(token);
    }

    if (!result.valid || !result.decoded) {
      throw new Error(result.error || 'Token validation failed');
    }

    return {
      id: result.decoded.sub || '',
      email: result.decoded.email || '',
      name: result.decoded.name || '',
      roles: result.decoded.roles || ['user'],
      sub: result.decoded.sub || '',
      exp: result.decoded.exp || 0,
      iat: result.decoded.iat || 0,
      provider: result.decoded.provider || 'jwt',
      providerId: result.decoded.sub || '',
      picture: result.decoded.picture,
      verified_email: result.decoded.email_verified,
    };
  }

  private detectTokenType(token: string): 'google' | 'jwt' {
    // Google ID tokens are JWTs but are longer than typical app-issued JWTs
    if (token.startsWith('eyJ') && token.length > 500) return 'google';
    return 'jwt';
  }
}

export const socialAuthMiddleware = new AuthenticationMiddleware(new SocialAuthVerifier(), {
  maxTokenAge: 3600,
  clockTolerance: 60,
});
```

Required environment variables for social auth:

```bash
GOOGLE_CLIENT_ID=your-google-client-id.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
```

Required dependencies:

```bash
npm install google-auth-library axios
```
