# How to Support Multiple Authentication Methods

This guide shows how to add JWT, OAuth, and API key authentication to a Noony application, and how to route a single endpoint through more than one method when your clients use different credentials.

## How to Add JWT Authentication

Configure RouteGuards once at startup with a JWT verifier, then attach `requirePermissions` to any handler that needs protection.

```typescript
// src/auth/jwt-auth.ts
import { RouteGuards, GuardSetup } from '@noony-serverless/core';
import { CustomTokenVerificationPort } from '@noony-serverless/core';
import jwt from 'jsonwebtoken';

interface JWTUser {
  sub: string;
  email: string;
  name: string;
  roles: string[];
  permissions: string[];
  exp: number;
  iat: number;
}

const jwtVerifier: CustomTokenVerificationPort<JWTUser> = {
  async verifyToken(token: string): Promise<JWTUser> {
    const secret = process.env.JWT_SECRET;
    if (!secret) throw new Error('JWT_SECRET environment variable not set');

    const payload = jwt.verify(token, secret, {
      algorithms: ['HS256', 'RS256'],
      issuer: process.env.JWT_ISSUER,
      audience: process.env.JWT_AUDIENCE,
    }) as any;

    if (!payload.sub || !payload.email) {
      throw new Error('Invalid JWT: missing required claims');
    }

    return {
      sub: payload.sub,
      email: payload.email,
      name: payload.name || payload.email,
      roles: payload.roles || [],
      permissions: payload.permissions || [],
      exp: payload.exp,
      iat: payload.iat,
    };
  },
};

export const setupJWTAuth = async () => {
  await RouteGuards.configureWithJWT(
    GuardSetup.production(),
    userPermissionSource,
    jwtVerifier,
    {
      tokenHeader: 'authorization',
      tokenPrefix: 'Bearer ',
      requireEmailVerification: true,
      allowInactiveUsers: false,
    }
  );
};
```

Usage in a handler:

```typescript
export const createUserHandler = new Handler<unknown, JWTUser>()
  .use(RouteGuards.requirePermissions(['user:create']))
  .handle(async (context) => {
    const user = context.user!;
    return { success: true, createdBy: user.email };
  });
```

## How to Add OAuth 2.0 Token Validation

Replace the JWT verifier with one that validates tokens against your OAuth provider's token introspection endpoint or JWKS endpoint. The handler code is identical — only the verifier changes.

```typescript
// src/auth/oauth-auth.ts
interface OAuthUser {
  sub: string;
  email: string;
  name: string;
  scope: string[];
  exp: number;
  client_id: string;
}

const oauthVerifier: CustomTokenVerificationPort<OAuthUser> = {
  async verifyToken(token: string): Promise<OAuthUser> {
    const response = await fetch(process.env.OAUTH_INTROSPECT_URL!, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: new URLSearchParams({ token }),
    });

    const tokenInfo = await response.json();
    if (!tokenInfo.active) throw new Error('Token is not active');

    return tokenInfo as OAuthUser;
  },
};

export const setupOAuthAuth = async () => {
  await RouteGuards.configureWithOAuth(
    GuardSetup.production(),
    userPermissionSource,
    oauthVerifier,
    {
      tokenHeader: 'authorization',
      tokenPrefix: 'Bearer ',
      requireEmailVerification: false,
    },
    ['read:profile', 'write:data'] // required OAuth scopes
  );
};
```

For JWKS-based validation (the preferred approach for Auth0, Google, Microsoft), see [OAuth2 Auth](./oauth2.md) for a complete `Auth0TokenValidator` implementation.

## How to Add API Key Authentication

API keys are validated by looking them up in a database rather than verifying a cryptographic signature. Use `configureWithAPIKey` and set `tokenHeader` to the custom header your clients use.

```typescript
// src/auth/api-key-auth.ts
interface APIKeyUser {
  keyId: string;
  permissions: string[];
  organization: string;
  isActive: boolean;
  expiresAt?: number;
}

const apiKeyVerifier: CustomTokenVerificationPort<APIKeyUser> = {
  async verifyToken(token: string): Promise<APIKeyUser> {
    const keyData = await validateAPIKeyInDatabase(token);
    if (!keyData || !keyData.isActive) {
      throw new Error('Invalid or inactive API key');
    }
    return keyData;
  },
};

export const setupAPIKeyAuth = async () => {
  await RouteGuards.configureWithAPIKey(
    GuardSetup.production(),
    userPermissionSource,
    apiKeyVerifier,
    {
      tokenHeader: 'x-api-key',
      tokenPrefix: '',
      allowInactiveUsers: false,
    },
    'keyId',     // field on APIKeyUser used as the user identifier
    'expiresAt'  // optional: field holding Unix timestamp expiration
  );
};
```

Usage:

```bash
curl -H "x-api-key: your-api-key-here" https://api.example.com/endpoint
```

## If You Need to Support More Than One Method in the Same App

When clients use different credentials — some send Bearer tokens, others send API keys — create a composite verifier that detects which method to use from the token format, then tries each in order.

```typescript
// src/auth/multi-auth.ts
import { CustomTokenVerificationPort } from '@noony-serverless/core';

interface MultiAuthUser {
  sub: string;
  email: string;
  roles: string[];
  permissions: string[];
  authMethod: 'jwt' | 'oauth' | 'apikey';
}

class MultiAuthVerifier implements CustomTokenVerificationPort<MultiAuthUser> {
  async verifyToken(token: string): Promise<MultiAuthUser> {
    // Detect method by token shape — not by a hint from the client
    if (this.looksLikeJWT(token)) {
      const user = await jwtVerifier.verifyToken(token);
      return { ...user, authMethod: 'jwt' };
    }

    if (this.looksLikeAPIKey(token)) {
      const user = await apiKeyVerifier.verifyToken(token);
      return { sub: user.keyId, email: '', roles: [], permissions: user.permissions, authMethod: 'apikey' };
    }

    // Fall back to OAuth introspection
    const user = await oauthVerifier.verifyToken(token);
    return { ...user, authMethod: 'oauth' };
  }

  private looksLikeJWT(token: string): boolean {
    // JWTs have exactly two dots and start with eyJ
    return token.startsWith('eyJ') && token.split('.').length === 3;
  }

  private looksLikeAPIKey(token: string): boolean {
    // API keys in this app start with a known prefix and contain no dots
    return (token.startsWith('ak_') || token.startsWith('sk_')) && !token.includes('.');
  }
}

export const setupMultiAuth = async () => {
  await RouteGuards.configure(
    GuardSetup.production(),
    userPermissionSource,
    new MultiAuthVerifier(),
    {
      tokenHeader: 'authorization',
      tokenPrefix: 'Bearer ',
      allowInactiveUsers: false,
    }
  );
};
```

Don't return the auth method in the error response — returning `"JWT validation failed"` instead of a plain `401` reveals which method failed and helps attackers enumerate valid strategies.

Don't try all three methods regardless of token shape. Attempting OAuth introspection on every request when most clients use JWT adds unnecessary latency. Use structural detection first.

## Cross-References

- Firebase token validation: [Firebase Auth](./firebase.md)
- Auth0, Google OAuth, and Microsoft Azure AD: [OAuth2 Auth](./oauth2.md)
- Full `configureWithJWT` / `configureWithAPIKey` signatures: [Route Guards Reference](./route-guards.md)
