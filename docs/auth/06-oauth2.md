# OAuth 2.0 Authentication with Noony Guards

Complete guide for integrating OAuth 2.0 authentication with Noony's Guard System for modern authentication and permission-based access control.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start (Auth0)](#quick-start-auth0)
- [Token Validators](#token-validators)
- [OAuth Grant Types](#oauth-grant-types)
- [Provider Integrations](#provider-integrations)
- [Permission Mapping](#permission-mapping)
- [Protected Handlers](#protected-handlers)
- [Advanced Usage](#advanced-usage)
- [Production Deployment](#production-deployment)
- [Troubleshooting](#troubleshooting)

## Overview

Noony's Guard System provides seamless integration with OAuth 2.0 providers, supporting modern authentication patterns with:

- **Multiple OAuth 2.0 Providers**: Auth0, Google, Microsoft, GitHub, Okta, and custom OIDC
- **All Grant Types**: Authorization Code, PKCE, Client Credentials, Refresh Token
- **JWKS Verification**: Automatic public key rotation and caching
- **Scope Mapping**: Convert OAuth scopes to Noony permissions
- **Token Introspection**: Support for opaque tokens
- **Sub-millisecond Checks**: High-performance permission validation with caching

### OAuth 2.0 vs OpenID Connect

This guide covers both:
- **OAuth 2.0**: Authorization framework for access delegation
- **OpenID Connect (OIDC)**: Authentication layer built on OAuth 2.0

Most modern providers (Auth0, Google, Microsoft) use OIDC, which provides ID tokens containing user identity claims.

## Prerequisites

- Node.js 18+ and npm
- OAuth 2.0 application registered with your provider
- `@noony-serverless/core` package installed
- Understanding of OAuth 2.0 grant types

## Installation

```bash
# Core dependencies
npm install @noony-serverless/core

# OAuth 2.0 and JWT libraries
npm install jose openid-client

# Provider-specific SDKs (optional)
npm install google-auth-library    # For Google OAuth
npm install @octokit/rest          # For GitHub OAuth
npm install @azure/msal-node       # For Microsoft OAuth

# Validation and utilities
npm install zod axios
```

## Quick Start (Auth0)

### 1. Register OAuth Application

Go to [Auth0 Dashboard](https://manage.auth0.com/):
1. Create new application (Regular Web Application)
2. Note your **Domain**, **Client ID**, and **Client Secret**
3. Configure callback URLs: `http://localhost:3000/callback`
4. Enable **RS256** algorithm for token signing

### 2. Environment Configuration

```bash
# .env
# Auth0 Configuration
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_AUDIENCE=https://your-api-identifier

# Application
NODE_ENV=production
NOONY_GUARD_CACHE_ENABLE=true
```

### 3. Create Auth0 Token Validator

```typescript
// src/auth/auth0-token-validator.ts
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { TokenValidator } from '@noony-serverless/core';

export interface Auth0Config {
  domain: string;
  audience: string;
  issuer?: string;
  clockTolerance?: number;
}

export class Auth0TokenValidator implements TokenValidator {
  private readonly config: Auth0Config;
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;
  private cache = new Map<string, { result: any; expiry: number }>();

  constructor(config: Auth0Config) {
    this.config = {
      issuer: `https://${config.domain}/`,
      clockTolerance: 60, // 60 seconds
      ...config,
    };

    // Create JWKS client for automatic key rotation
    this.jwks = createRemoteJWKSet(
      new URL(`https://${config.domain}/.well-known/jwks.json`)
    );
  }

  async validateToken(token: string): Promise<{
    valid: boolean;
    decoded?: any;
    error?: string;
  }> {
    try {
      // Check cache
      const cached = this.getCachedResult(token);
      if (cached) return cached;

      // Verify JWT with JWKS
      const { payload } = await jwtVerify(token, this.jwks, {
        issuer: this.config.issuer,
        audience: this.config.audience,
        clockTolerance: this.config.clockTolerance,
      });

      // Validate required claims
      if (!payload.sub) {
        throw new Error('Token missing sub claim');
      }

      const result = {
        valid: true,
        decoded: {
          sub: payload.sub as string,
          email: payload.email as string,
          name: payload.name as string,
          picture: payload.picture as string,
          email_verified: payload.email_verified as boolean,
          // Auth0 custom claims
          permissions: payload.permissions as string[] || [],
          roles: payload['https://your-app/roles'] as string[] || [],
          // Standard claims
          iss: payload.iss,
          aud: payload.aud,
          exp: payload.exp,
          iat: payload.iat,
        },
      };

      // Cache successful result
      this.setCachedResult(token, result);
      return result;
    } catch (error: any) {
      return {
        valid: false,
        error: this.extractError(error),
      };
    }
  }

  extractUserId(decoded: any): string {
    return decoded.sub || '';
  }

  isTokenExpired(decoded: any): boolean {
    if (!decoded.exp) return false;
    const now = Math.floor(Date.now() / 1000);
    return decoded.exp <= now;
  }

  private extractError(error: any): string {
    if (error.code === 'ERR_JWT_EXPIRED') {
      return 'Auth0 token has expired';
    }
    if (error.code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') {
      return 'Invalid token signature';
    }
    if (error.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED') {
      return `Token validation failed: ${error.claim}`;
    }
    return error.message || 'Auth0 token validation failed';
  }

  private getCachedResult(token: string): any | null {
    const key = this.getCacheKey(token);
    const entry = this.cache.get(key);
    if (entry && Date.now() < entry.expiry) {
      return { ...entry.result, metadata: { cached: true } };
    }
    if (entry) this.cache.delete(key);
    return null;
  }

  private setCachedResult(token: string, result: any): void {
    const key = this.getCacheKey(token);
    const ttl = this.getCacheTTL(result.decoded);
    this.cache.set(key, { result, expiry: Date.now() + ttl });

    // Cleanup old entries
    if (this.cache.size > 1000) {
      this.cleanupCache();
    }
  }

  private getCacheKey(token: string): string {
    return token.substring(0, 16);
  }

  private getCacheTTL(decoded?: any): number {
    if (!decoded?.exp) return 5 * 60 * 1000; // 5 minutes default

    const now = Math.floor(Date.now() / 1000);
    const timeToExpiry = decoded.exp - now;
    const cacheDuration = Math.floor(timeToExpiry / 2);

    return Math.max(60 * 1000, Math.min(cacheDuration * 1000, 30 * 60 * 1000));
  }

  private cleanupCache(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiry) {
        this.cache.delete(key);
      }
    }
  }

  public clearCache(): void {
    this.cache.clear();
  }
}
```

### 4. Configure Guards

```typescript
// src/config/guard.config.ts
import { RouteGuards, GuardSetup } from '@noony-serverless/core';
import { Auth0TokenValidator } from '../auth/auth0-token-validator';
import { Auth0PermissionSource } from '../permissions/auth0-permission-source';

// Initialize Auth0 token validator
const tokenValidator = new Auth0TokenValidator({
  domain: process.env.AUTH0_DOMAIN!,
  audience: process.env.AUTH0_AUDIENCE!,
});

// Initialize permission source
const permissionSource = new Auth0PermissionSource();

// Configure guards
const guardProfile =
  process.env.NODE_ENV === 'production'
    ? GuardSetup.production()
    : GuardSetup.development();

export const routeGuards = new RouteGuards(guardProfile);

routeGuards.initialize({
  tokenValidator,
  permissionSource,
  authConfig: {
    tokenHeader: 'authorization',
    tokenPrefix: 'Bearer ',
    requireEmailVerification: false,
    allowInactiveUsers: false,
  },
});

export { tokenValidator, permissionSource };
```

### 5. Create Protected Endpoint

```typescript
// src/handlers/user.handler.ts
import { Handler } from '@noony-serverless/core';
import { routeGuards } from '../config/guard.config';

export const getUserHandler = new Handler()
  .use(routeGuards.requireAuth())
  .use(routeGuards.requirePermission('users:read'))
  .handle(async (context) => {
    // context.user contains Auth0 user data
    const user = context.user!;

    context.res.status(200).json({
      success: true,
      data: {
        userId: user.sub,
        email: user.email,
        permissions: user.permissions,
      },
    });
  });
```

### 6. Make Authenticated Request

```bash
# Get access token from Auth0 (using authorization code flow)
# Then make request with token
curl -X GET https://your-api.com/users \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## Token Validators

### Auth0 Token Validator (Complete)

Full implementation shown in Quick Start above. Key features:
- ✅ JWKS-based verification with automatic key rotation
- ✅ Audience and issuer validation
- ✅ Clock tolerance for time skew
- ✅ Custom claims extraction
- ✅ Intelligent caching with TTL
- ✅ Comprehensive error handling

### Google OAuth Validator

```typescript
// src/auth/google-oauth-validator.ts
import { OAuth2Client } from 'google-auth-library';
import { TokenValidator } from '@noony-serverless/core';

export interface GoogleOAuthConfig {
  clientId: string;
  hostedDomain?: string; // For G Suite domain restriction
}

export class GoogleOAuthValidator implements TokenValidator {
  private readonly client: OAuth2Client;
  private readonly config: GoogleOAuthConfig;
  private cache = new Map<string, { result: any; expiry: number }>();

  constructor(config: GoogleOAuthConfig) {
    this.config = config;
    this.client = new OAuth2Client(config.clientId);
  }

  async validateToken(token: string): Promise<{
    valid: boolean;
    decoded?: any;
    error?: string;
  }> {
    try {
      // Check cache
      const cached = this.getCachedResult(token);
      if (cached) return cached;

      // Verify Google ID token
      const ticket = await this.client.verifyIdToken({
        idToken: token,
        audience: this.config.clientId,
      });

      const payload = ticket.getPayload();
      if (!payload) {
        throw new Error('Invalid token payload');
      }

      // Validate hosted domain if configured
      if (this.config.hostedDomain && payload.hd !== this.config.hostedDomain) {
        throw new Error(`Token not from required domain: ${this.config.hostedDomain}`);
      }

      const result = {
        valid: true,
        decoded: {
          sub: payload.sub,
          email: payload.email!,
          name: payload.name || '',
          picture: payload.picture || '',
          email_verified: payload.email_verified || false,
          hd: payload.hd, // Hosted domain
          // Map Google scopes to permissions
          permissions: this.mapGoogleScopes(payload),
          // Standard claims
          iss: payload.iss,
          aud: payload.aud,
          exp: payload.exp,
          iat: payload.iat,
        },
      };

      this.setCachedResult(token, result);
      return result;
    } catch (error: any) {
      return {
        valid: false,
        error: error.message || 'Google OAuth validation failed',
      };
    }
  }

  extractUserId(decoded: any): string {
    return decoded.sub || '';
  }

  isTokenExpired(decoded: any): boolean {
    if (!decoded.exp) return false;
    return decoded.exp <= Math.floor(Date.now() / 1000);
  }

  private mapGoogleScopes(payload: any): string[] {
    // Map Google OAuth scopes to application permissions
    const permissions: string[] = [];

    // Example: Map based on email domain or custom claims
    if (payload.email?.endsWith('@company.com')) {
      permissions.push('users:read', 'resources:read');

      if (payload.email.includes('admin')) {
        permissions.push('users:write', 'admin:access');
      }
    }

    return permissions;
  }

  private getCachedResult(token: string): any | null {
    const key = this.getCacheKey(token);
    const entry = this.cache.get(key);
    if (entry && Date.now() < entry.expiry) {
      return { ...entry.result, metadata: { cached: true } };
    }
    if (entry) this.cache.delete(key);
    return null;
  }

  private setCachedResult(token: string, result: any): void {
    const key = this.getCacheKey(token);
    const ttl = 5 * 60 * 1000; // 5 minutes
    this.cache.set(key, { result, expiry: Date.now() + ttl });
  }

  private getCacheKey(token: string): string {
    return token.substring(0, 16);
  }

  public clearCache(): void {
    this.cache.clear();
  }
}
```

### Microsoft Azure AD Validator

```typescript
// src/auth/microsoft-oauth-validator.ts
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { TokenValidator } from '@noony-serverless/core';

export interface MicrosoftOAuthConfig {
  tenantId: string;
  clientId: string;
  validateIssuer?: boolean;
}

export class MicrosoftOAuthValidator implements TokenValidator {
  private readonly config: MicrosoftOAuthConfig;
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;
  private cache = new Map<string, { result: any; expiry: number }>();

  constructor(config: MicrosoftOAuthConfig) {
    this.config = {
      validateIssuer: true,
      ...config,
    };

    // Microsoft JWKS endpoint
    this.jwks = createRemoteJWKSet(
      new URL(
        `https://login.microsoftonline.com/${config.tenantId}/discovery/v2.0/keys`
      )
    );
  }

  async validateToken(token: string): Promise<{
    valid: boolean;
    decoded?: any;
    error?: string;
  }> {
    try {
      const cached = this.getCachedResult(token);
      if (cached) return cached;

      // Verify JWT with Microsoft's JWKS
      const { payload } = await jwtVerify(token, this.jwks, {
        issuer: this.config.validateIssuer
          ? `https://login.microsoftonline.com/${this.config.tenantId}/v2.0`
          : undefined,
        audience: this.config.clientId,
        clockTolerance: 60,
      });

      const result = {
        valid: true,
        decoded: {
          sub: payload.sub || payload.oid as string,
          email: payload.email as string || payload.upn as string,
          name: payload.name as string,
          // Azure AD specific claims
          tid: payload.tid, // Tenant ID
          roles: payload.roles as string[] || [],
          groups: payload.groups as string[] || [],
          scp: payload.scp, // Scopes
          // Map roles to permissions
          permissions: this.mapAzureRoles(payload.roles as string[] || []),
          // Standard claims
          iss: payload.iss,
          aud: payload.aud,
          exp: payload.exp,
          iat: payload.iat,
        },
      };

      this.setCachedResult(token, result);
      return result;
    } catch (error: any) {
      return {
        valid: false,
        error: error.message || 'Microsoft OAuth validation failed',
      };
    }
  }

  extractUserId(decoded: any): string {
    return decoded.sub || decoded.oid || '';
  }

  isTokenExpired(decoded: any): boolean {
    if (!decoded.exp) return false;
    return decoded.exp <= Math.floor(Date.now() / 1000);
  }

  private mapAzureRoles(roles: string[]): string[] {
    // Map Azure AD roles to application permissions
    const rolePermissionMap: Record<string, string[]> = {
      'Admin': ['admin:*', 'users:*', 'resources:*'],
      'User.Read': ['users:read'],
      'User.ReadWrite': ['users:read', 'users:write'],
      'Files.Read': ['files:read'],
      'Files.ReadWrite': ['files:read', 'files:write'],
    };

    const permissions = new Set<string>();
    roles.forEach(role => {
      const mapped = rolePermissionMap[role] || [];
      mapped.forEach(p => permissions.add(p));
    });

    return Array.from(permissions);
  }

  private getCachedResult(token: string): any | null {
    const key = this.getCacheKey(token);
    const entry = this.cache.get(key);
    if (entry && Date.now() < entry.expiry) {
      return { ...entry.result, metadata: { cached: true } };
    }
    if (entry) this.cache.delete(key);
    return null;
  }

  private setCachedResult(token: string, result: any): void {
    const key = this.getCacheKey(token);
    const ttl = 5 * 60 * 1000;
    this.cache.set(key, { result, expiry: Date.now() + ttl });
  }

  private getCacheKey(token: string): string {
    return token.substring(0, 16);
  }

  public clearCache(): void {
    this.cache.clear();
  }
}
```

### GitHub OAuth Validator

```typescript
// src/auth/github-oauth-validator.ts
import { Octokit } from '@octokit/rest';
import { TokenValidator } from '@noony-serverless/core';

export class GitHubOAuthValidator implements TokenValidator {
  private cache = new Map<string, { result: any; expiry: number }>();

  async validateToken(token: string): Promise<{
    valid: boolean;
    decoded?: any;
    error?: string;
  }> {
    try {
      const cached = this.getCachedResult(token);
      if (cached) return cached;

      // GitHub uses opaque tokens, not JWTs
      // Validate by calling GitHub API
      const octokit = new Octokit({ auth: token });

      // Get authenticated user
      const { data: user } = await octokit.users.getAuthenticated();

      // Get user's organizations for role mapping
      const { data: orgs } = await octokit.orgs.listForAuthenticatedUser();

      const result = {
        valid: true,
        decoded: {
          sub: user.id.toString(),
          email: user.email || '',
          name: user.name || user.login,
          username: user.login,
          picture: user.avatar_url,
          // GitHub specific
          github_id: user.id,
          organizations: orgs.map(o => o.login),
          // Map organizations to permissions
          permissions: this.mapGitHubPerms(user, orgs),
          // Simulated standard claims
          iss: 'github.com',
          aud: 'api',
          exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
          iat: Math.floor(Date.now() / 1000),
        },
      };

      this.setCachedResult(token, result);
      return result;
    } catch (error: any) {
      if (error.status === 401) {
        return { valid: false, error: 'Invalid GitHub token' };
      }
      return {
        valid: false,
        error: error.message || 'GitHub OAuth validation failed',
      };
    }
  }

  extractUserId(decoded: any): string {
    return decoded.sub || decoded.github_id?.toString() || '';
  }

  isTokenExpired(decoded: any): boolean {
    if (!decoded.exp) return false;
    return decoded.exp <= Math.floor(Date.now() / 1000);
  }

  private mapGitHubPerms(user: any, orgs: any[]): string[] {
    const permissions: string[] = ['repos:read'];

    // Example: Admin permissions for organization owners
    const adminOrgs = orgs.filter(o => o.role === 'admin');
    if (adminOrgs.length > 0) {
      permissions.push('admin:access', 'users:write');
    }

    return permissions;
  }

  private getCachedResult(token: string): any | null {
    const key = this.getCacheKey(token);
    const entry = this.cache.get(key);
    if (entry && Date.now() < entry.expiry) {
      return { ...entry.result, metadata: { cached: true } };
    }
    if (entry) this.cache.delete(key);
    return null;
  }

  private setCachedResult(token: string, result: any): void {
    const key = this.getCacheKey(token);
    const ttl = 5 * 60 * 1000;
    this.cache.set(key, { result, expiry: Date.now() + ttl });
  }

  private getCacheKey(token: string): string {
    return token.substring(0, 16);
  }

  public clearCache(): void {
    this.cache.clear();
  }
}
```

## OAuth Grant Types

### Authorization Code Flow (Traditional Web Apps)

```typescript
// src/auth/oauth-flows.ts
import axios from 'axios';

export interface AuthorizationCodeConfig {
  authorizationEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope: string;
}

export class AuthorizationCodeFlow {
  constructor(private config: AuthorizationCodeConfig) {}

  /**
   * Step 1: Generate authorization URL
   */
  getAuthorizationUrl(state: string): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: this.config.scope,
      state, // CSRF protection
    });

    return `${this.config.authorizationEndpoint}?${params.toString()}`;
  }

  /**
   * Step 2: Exchange authorization code for tokens
   */
  async exchangeCodeForTokens(code: string): Promise<{
    access_token: string;
    id_token?: string;
    refresh_token?: string;
    expires_in: number;
  }> {
    const response = await axios.post(
      this.config.tokenEndpoint,
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: this.config.redirectUri,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
      }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );

    return response.data;
  }

  /**
   * Step 3: Refresh access token
   */
  async refreshAccessToken(refreshToken: string): Promise<{
    access_token: string;
    expires_in: number;
  }> {
    const response = await axios.post(
      this.config.tokenEndpoint,
      new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
      }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );

    return response.data;
  }
}

// Usage example
const auth0Flow = new AuthorizationCodeFlow({
  authorizationEndpoint: `https://${process.env.AUTH0_DOMAIN}/authorize`,
  tokenEndpoint: `https://${process.env.AUTH0_DOMAIN}/oauth/token`,
  clientId: process.env.AUTH0_CLIENT_ID!,
  clientSecret: process.env.AUTH0_CLIENT_SECRET!,
  redirectUri: 'http://localhost:3000/callback',
  scope: 'openid profile email',
});

// In your login route
app.get('/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state; // Store state for validation
  const authUrl = auth0Flow.getAuthorizationUrl(state);
  res.redirect(authUrl);
});

// In your callback route
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;

  // Validate state (CSRF protection)
  if (state !== req.session.oauthState) {
    return res.status(400).send('Invalid state parameter');
  }

  try {
    const tokens = await auth0Flow.exchangeCodeForTokens(code as string);

    // Store tokens securely
    req.session.accessToken = tokens.access_token;
    req.session.refreshToken = tokens.refresh_token;

    res.redirect('/dashboard');
  } catch (error) {
    res.status(500).send('Authentication failed');
  }
});
```

### PKCE Flow (SPAs and Mobile Apps)

```typescript
// src/auth/pkce-flow.ts
import crypto from 'crypto';
import axios from 'axios';

export class PKCEFlow {
  constructor(private config: {
    authorizationEndpoint: string;
    tokenEndpoint: string;
    clientId: string;
    redirectUri: string;
    scope: string;
  }) {}

  /**
   * Generate code verifier and challenge
   */
  generatePKCE(): {
    codeVerifier: string;
    codeChallenge: string;
  } {
    // Generate random code verifier (43-128 characters)
    const codeVerifier = crypto.randomBytes(32).toString('base64url');

    // Generate code challenge (SHA256 hash of verifier)
    const codeChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');

    return { codeVerifier, codeChallenge };
  }

  /**
   * Step 1: Generate authorization URL with PKCE
   */
  getAuthorizationUrl(
    codeChallenge: string,
    state: string
  ): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: this.config.scope,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    return `${this.config.authorizationEndpoint}?${params.toString()}`;
  }

  /**
   * Step 2: Exchange code for tokens (no client secret needed!)
   */
  async exchangeCodeForTokens(
    code: string,
    codeVerifier: string
  ): Promise<{
    access_token: string;
    id_token?: string;
    expires_in: number;
  }> {
    const response = await axios.post(
      this.config.tokenEndpoint,
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: this.config.redirectUri,
        client_id: this.config.clientId,
        code_verifier: codeVerifier, // Proves we generated the challenge
      }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );

    return response.data;
  }
}

// Frontend usage (React example)
const pkceFlow = new PKCEFlow({
  authorizationEndpoint: `https://${AUTH0_DOMAIN}/authorize`,
  tokenEndpoint: `https://${AUTH0_DOMAIN}/oauth/token`,
  clientId: AUTH0_CLIENT_ID,
  redirectUri: 'http://localhost:3000/callback',
  scope: 'openid profile email',
});

// Login button click
async function handleLogin() {
  const { codeVerifier, codeChallenge } = pkceFlow.generatePKCE();
  const state = crypto.randomBytes(16).toString('hex');

  // Store in session storage (client-side)
  sessionStorage.setItem('pkce_verifier', codeVerifier);
  sessionStorage.setItem('oauth_state', state);

  const authUrl = pkceFlow.getAuthorizationUrl(codeChallenge, state);
  window.location.href = authUrl;
}

// Callback handler
async function handleCallback() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  const state = params.get('state');

  // Validate state
  if (state !== sessionStorage.getItem('oauth_state')) {
    throw new Error('Invalid state');
  }

  const codeVerifier = sessionStorage.getItem('pkce_verifier')!;

  const tokens = await pkceFlow.exchangeCodeForTokens(code!, codeVerifier);

  // Store tokens
  localStorage.setItem('access_token', tokens.access_token);

  // Clean up
  sessionStorage.removeItem('pkce_verifier');
  sessionStorage.removeItem('oauth_state');

  // Redirect to app
  window.location.href = '/dashboard';
}
```

### Client Credentials Flow (Server-to-Server)

```typescript
// src/auth/client-credentials-flow.ts
import axios from 'axios';

export class ClientCredentialsFlow {
  constructor(private config: {
    tokenEndpoint: string;
    clientId: string;
    clientSecret: string;
    audience?: string;
  }) {}

  /**
   * Get machine-to-machine access token
   */
  async getAccessToken(): Promise<{
    access_token: string;
    expires_in: number;
    token_type: string;
  }> {
    const response = await axios.post(
      this.config.tokenEndpoint,
      new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        ...(this.config.audience && { audience: this.config.audience }),
      }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );

    return response.data;
  }
}

// Usage: Backend service calling another API
const m2mFlow = new ClientCredentialsFlow({
  tokenEndpoint: `https://${process.env.AUTH0_DOMAIN}/oauth/token`,
  clientId: process.env.M2M_CLIENT_ID!,
  clientSecret: process.env.M2M_CLIENT_SECRET!,
  audience: 'https://api.example.com',
});

// Get token and call protected API
async function callProtectedAPI() {
  const { access_token } = await m2mFlow.getAccessToken();

  const response = await axios.get('https://api.example.com/data', {
    headers: {
      Authorization: `Bearer ${access_token}`,
    },
  });

  return response.data;
}
```

## Permission Mapping

### Scope-to-Permission Mapping

```typescript
// src/permissions/scope-mapper.ts

export interface ScopeMappingStrategy {
  mapScopes(scopes: string[], userClaims: any): Promise<string[]>;
}

/**
 * Direct Mapping Strategy
 * OAuth scope → Noony permission (1:1)
 */
export class DirectScopeMapper implements ScopeMappingStrategy {
  private scopeMap: Record<string, string[]> = {
    // OAuth scopes → Noony permissions
    'read:users': ['users:read'],
    'write:users': ['users:write', 'users:update'],
    'delete:users': ['users:delete'],
    'admin': ['admin:*', 'users:*', 'resources:*'],
  };

  async mapScopes(scopes: string[]): Promise<string[]> {
    const permissions = new Set<string>();

    scopes.forEach(scope => {
      const mapped = this.scopeMap[scope] || [];
      mapped.forEach(p => permissions.add(p));
    });

    return Array.from(permissions);
  }
}

/**
 * Role-Based Mapping Strategy
 * Extract roles from token, map roles to permissions
 */
export class RoleBasedMapper implements ScopeMappingStrategy {
  private roleMap: Record<string, string[]> = {
    'admin': ['admin:*', 'users:*', 'resources:*'],
    'manager': ['users:read', 'users:update', 'reports:read'],
    'developer': ['code:read', 'code:write', 'deploys:read'],
    'user': ['profile:read', 'profile:update'],
  };

  async mapScopes(scopes: string[], userClaims: any): Promise<string[]> {
    const roles = userClaims.roles || [];
    const permissions = new Set<string>();

    // Map OAuth scopes
    scopes.forEach(scope => {
      if (scope.startsWith('role:')) {
        const role = scope.substring(5);
        const mapped = this.roleMap[role] || [];
        mapped.forEach(p => permissions.add(p));
      }
    });

    // Map token role claims
    roles.forEach((role: string) => {
      const mapped = this.roleMap[role] || [];
      mapped.forEach(p => permissions.add(p));
    });

    return Array.from(permissions);
  }
}

/**
 * Custom Mapping Strategy
 * Dynamic permission resolution based on user attributes
 */
export class CustomMapper implements ScopeMappingStrategy {
  async mapScopes(scopes: string[], userClaims: any): Promise<string[]> {
    const permissions = new Set<string>();

    // Base permissions for all authenticated users
    permissions.add('profile:read');

    // Email-based permissions
    if (userClaims.email?.endsWith('@company.com')) {
      permissions.add('internal:access');
      permissions.add('docs:read');
    }

    // Department-based permissions
    if (userClaims.department === 'engineering') {
      permissions.add('code:read');
      permissions.add('deployments:read');
    }

    if (userClaims.department === 'finance') {
      permissions.add('invoices:read');
      permissions.add('reports:read');
    }

    // Admin flag
    if (userClaims.is_admin === true) {
      permissions.add('admin:*');
    }

    // Map OAuth scopes to permissions
    scopes.forEach(scope => {
      // Convert OAuth scope format to permission format
      // Example: "read:users" → "users:read"
      const [action, resource] = scope.split(':');
      if (action && resource) {
        permissions.add(`${resource}:${action}`);
      }
    });

    return Array.from(permissions);
  }
}

/**
 * Permission Source using Scope Mapper
 */
export class OAuth2PermissionSource implements UserPermissionSource {
  constructor(private mapper: ScopeMappingStrategy) {}

  async getUserPermissions(userId: string): Promise<string[]> {
    // In OAuth 2.0, permissions come from the token itself
    // This method is called by the Guard System with user context
    // The token validator should have already populated permissions

    // If you need to fetch additional permissions from a database:
    // const userDoc = await db.collection('users').doc(userId).get();
    // return userDoc.data()?.additionalPermissions || [];

    // For OAuth 2.0, permissions are typically in the token
    return [];
  }
}
```

### Auth0 Permission Source

```typescript
// src/permissions/auth0-permission-source.ts
import { UserPermissionSource } from '@noony-serverless/core';

export class Auth0PermissionSource implements UserPermissionSource {
  async getUserPermissions(userId: string): Promise<string[]> {
    // Auth0 includes permissions directly in the access token
    // The token validator extracts them during validation
    // This source can fetch additional permissions if needed

    // Example: Fetch user-specific permissions from your database
    // const user = await db.collection('users').doc(userId).get();
    // return user.data()?.customPermissions || [];

    // For Auth0, permissions are in the token, so return empty
    // unless you have additional permission sources
    return [];
  }
}
```

## Protected Handlers

### Basic Protected Endpoint

```typescript
// src/handlers/resource.handlers.ts
import { Handler, Context } from '@noony-serverless/core';
import { routeGuards } from '../config/guard.config';
import { z } from 'zod';
import { BodyValidationMiddleware } from '@noony-serverless/core';

// Request schemas
const createResourceSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500),
  type: z.enum(['document', 'image', 'video']),
});

type CreateResourceRequest = z.infer<typeof createResourceSchema>;

/**
 * Create resource
 * Requires: OAuth authentication + "resources:create" permission
 */
export const createResourceHandler = new Handler<CreateResourceRequest>()
  .use(routeGuards.requireAuth())
  .use(routeGuards.requirePermission('resources:create'))
  .use(new BodyValidationMiddleware(createResourceSchema))
  .handle(async (context: Context<CreateResourceRequest>) => {
    const user = context.user!;
    const data = context.req.validatedBody!;

    console.log(`User ${user.email} creating resource: ${data.name}`);

    const resource = await resourceService.create({
      ...data,
      createdBy: user.sub,
      createdAt: new Date(),
    });

    context.res.status(201).json({
      success: true,
      data: resource,
    });
  });

/**
 * Get resource
 * Requires: "resources:read" OR "admin:access"
 */
export const getResourceHandler = new Handler()
  .use(routeGuards.requireAuth())
  .use(routeGuards.requireAnyPermission(['resources:read', 'admin:access']))
  .handle(async (context) => {
    const resourceId = context.req.params?.resourceId;
    const resource = await resourceService.getById(resourceId);

    if (!resource) {
      context.res.status(404).json({
        success: false,
        error: 'Resource not found',
      });
      return;
    }

    context.res.status(200).json({
      success: true,
      data: resource,
    });
  });

/**
 * Delete resource
 * Requires: BOTH "resources:delete" AND "admin:access"
 */
export const deleteResourceHandler = new Handler()
  .use(routeGuards.requireAuth())
  .use(routeGuards.requireAllPermissions(['resources:delete', 'admin:access']))
  .handle(async (context) => {
    const resourceId = context.req.params?.resourceId;
    await resourceService.delete(resourceId);

    context.res.status(200).json({
      success: true,
      message: 'Resource deleted successfully',
    });
  });
```

### Admin Endpoints

```typescript
/**
 * Admin dashboard
 * Requires: Complex permission expression
 */
export const adminDashboardHandler = new Handler()
  .use(routeGuards.requireAuth())
  .use(
    routeGuards.requirePermission({
      expression: '(admin:* OR superuser:*) AND dashboard:access',
    })
  )
  .handle(async (context) => {
    const stats = await adminService.getDashboardStats();

    context.res.status(200).json({
      success: true,
      data: stats,
    });
  });

/**
 * User management
 * Requires: Wildcard "users:*" permission
 */
export const manageUsersHandler = new Handler()
  .use(routeGuards.requireAuth())
  .use(routeGuards.requirePermission('users:*'))
  .handle(async (context) => {
    const action = context.req.query?.action as string;
    const userId = context.req.query?.userId as string;

    // User has full access to all user operations
    switch (action) {
      case 'list':
        const users = await userService.list();
        context.res.json({ success: true, data: users });
        break;
      case 'update':
        await userService.update(userId, context.req.body);
        context.res.json({ success: true });
        break;
      case 'delete':
        await userService.delete(userId);
        context.res.json({ success: true });
        break;
      default:
        context.res.status(400).json({ error: 'Invalid action' });
    }
  });
```

## Advanced Usage

### Multi-Provider Configuration

```typescript
// src/config/multi-provider-guard.config.ts
import { RouteGuards, GuardSetup } from '@noony-serverless/core';
import { Auth0TokenValidator } from '../auth/auth0-token-validator';
import { GoogleOAuthValidator } from '../auth/google-oauth-validator';
import { MicrosoftOAuthValidator } from '../auth/microsoft-oauth-validator';

/**
 * Multi-provider token validator with automatic failover
 */
class MultiProviderTokenValidator implements TokenValidator {
  private validators: {
    name: string;
    validator: TokenValidator;
    priority: number;
  }[];

  constructor() {
    this.validators = [
      {
        name: 'Auth0',
        validator: new Auth0TokenValidator({
          domain: process.env.AUTH0_DOMAIN!,
          audience: process.env.AUTH0_AUDIENCE!,
        }),
        priority: 1,
      },
      {
        name: 'Google',
        validator: new GoogleOAuthValidator({
          clientId: process.env.GOOGLE_CLIENT_ID!,
        }),
        priority: 2,
      },
      {
        name: 'Microsoft',
        validator: new MicrosoftOAuthValidator({
          tenantId: process.env.AZURE_TENANT_ID!,
          clientId: process.env.AZURE_CLIENT_ID!,
        }),
        priority: 3,
      },
    ].sort((a, b) => a.priority - b.priority);
  }

  async validateToken(token: string): Promise<{
    valid: boolean;
    decoded?: any;
    error?: string;
  }> {
    // Try each validator in priority order
    for (const { name, validator } of this.validators) {
      try {
        const result = await validator.validateToken(token);
        if (result.valid) {
          console.log(`✅ Token validated by ${name}`);
          return result;
        }
      } catch (error) {
        console.warn(`⚠️ ${name} validation failed, trying next provider`);
        continue;
      }
    }

    return {
      valid: false,
      error: 'Token validation failed for all providers',
    };
  }

  extractUserId(decoded: any): string {
    return decoded.sub || '';
  }

  isTokenExpired(decoded: any): boolean {
    return decoded.exp ? decoded.exp <= Math.floor(Date.now() / 1000) : false;
  }
}

// Use multi-provider validator
export const routeGuards = new RouteGuards(GuardSetup.production());

routeGuards.initialize({
  tokenValidator: new MultiProviderTokenValidator(),
  permissionSource: new OAuth2PermissionSource(new CustomMapper()),
  authConfig: {
    tokenHeader: 'authorization',
    tokenPrefix: 'Bearer ',
  },
});
```

### Dynamic Permission Checking

```typescript
/**
 * Resource access with ownership check
 */
export const accessResourceHandler = new Handler()
  .use(routeGuards.requireAuth())
  .handle(async (context) => {
    const resourceId = context.req.params?.resourceId;
    const user = context.user!;

    // Fetch resource
    const resource = await resourceService.getById(resourceId);

    if (!resource) {
      context.res.status(404).json({ error: 'Not found' });
      return;
    }

    // Check if user owns the resource OR has admin permission
    const isOwner = resource.createdBy === user.sub;
    const hasAdminPerm = await routeGuards.checkPermission(
      context,
      'admin:access'
    );

    if (!isOwner && !hasAdminPerm) {
      context.res.status(403).json({
        error: 'You can only access your own resources',
      });
      return;
    }

    context.res.status(200).json({
      success: true,
      data: resource,
    });
  });
```

### Token Introspection (for Opaque Tokens)

```typescript
// src/auth/token-introspection.ts
import axios from 'axios';
import { TokenValidator } from '@noony-serverless/core';

/**
 * OAuth 2.0 Token Introspection Validator
 * For opaque (non-JWT) access tokens
 */
export class TokenIntrospectionValidator implements TokenValidator {
  constructor(private config: {
    introspectionEndpoint: string;
    clientId: string;
    clientSecret: string;
  }) {}

  async validateToken(token: string): Promise<{
    valid: boolean;
    decoded?: any;
    error?: string;
  }> {
    try {
      // Call introspection endpoint
      const response = await axios.post(
        this.config.introspectionEndpoint,
        new URLSearchParams({
          token,
          token_type_hint: 'access_token',
        }),
        {
          auth: {
            username: this.config.clientId,
            password: this.config.clientSecret,
          },
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        }
      );

      const introspection = response.data;

      if (!introspection.active) {
        return {
          valid: false,
          error: 'Token is not active',
        };
      }

      return {
        valid: true,
        decoded: {
          sub: introspection.sub,
          email: introspection.email,
          scope: introspection.scope?.split(' ') || [],
          permissions: this.mapScopes(introspection.scope?.split(' ') || []),
          exp: introspection.exp,
          iat: introspection.iat,
        },
      };
    } catch (error: any) {
      return {
        valid: false,
        error: error.message || 'Token introspection failed',
      };
    }
  }

  extractUserId(decoded: any): string {
    return decoded.sub || '';
  }

  isTokenExpired(decoded: any): boolean {
    return decoded.exp ? decoded.exp <= Math.floor(Date.now() / 1000) : false;
  }

  private mapScopes(scopes: string[]): string[] {
    // Map OAuth scopes to permissions
    const scopeMap: Record<string, string[]> = {
      'read:users': ['users:read'],
      'write:users': ['users:write'],
      'admin': ['admin:*'],
    };

    const permissions = new Set<string>();
    scopes.forEach(scope => {
      const mapped = scopeMap[scope] || [];
      mapped.forEach(p => permissions.add(p));
    });

    return Array.from(permissions);
  }
}
```

## Production Deployment

### Security Checklist

```bash
# Environment variables for production
NODE_ENV=production

# OAuth Provider Configuration
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_AUDIENCE=https://your-api-identifier
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret  # Server-side only!

# Token Configuration
JWT_ISSUER=https://your-tenant.auth0.com/
JWT_AUDIENCE=https://your-api-identifier
JWT_CLOCK_TOLERANCE=60  # 60 seconds

# Guard System
NOONY_GUARD_CACHE_ENABLE=true
NOONY_GUARD_CACHE_TTL=300000  # 5 minutes

# Security
REQUIRE_EMAIL_VERIFIED=true
ALLOW_INACTIVE_USERS=false
ENABLE_RATE_LIMITING=true
MAX_REQUESTS_PER_MINUTE=100
```

### PKCE Enforcement

```typescript
// Enforce PKCE for public clients (SPAs, mobile)
// In Auth0 Dashboard:
// Application Settings → Advanced Settings → Grant Types
// ✅ Enable "Authorization Code"
// ✅ Require PKCE for public clients
// ❌ Disable "Implicit"

// Code enforcement
export const enforceP KCE = (req: Request, res: Response, next: NextFunction) => {
  const isPublicClient = req.body.client_id && !req.body.client_secret;

  if (isPublicClient && !req.body.code_verifier) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'PKCE is required for public clients',
    });
  }

  next();
};
```

### Token Rotation

```typescript
// Implement refresh token rotation
export const refreshTokenHandler = new Handler()
  .handle(async (context) => {
    const refreshToken = context.req.body?.refresh_token;

    if (!refreshToken) {
      context.res.status(400).json({
        error: 'refresh_token required',
      });
      return;
    }

    try {
      // Exchange refresh token for new access token
      const tokens = await authFlow.refreshAccessToken(refreshToken);

      // Revoke old refresh token (rotation)
      await revokeRefreshToken(refreshToken);

      context.res.status(200).json({
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token, // New refresh token
        expires_in: tokens.expires_in,
        token_type: 'Bearer',
      });
    } catch (error) {
      context.res.status(401).json({
        error: 'invalid_grant',
        error_description: 'Invalid refresh token',
      });
    }
  });
```

### Cloud Functions Deployment

```bash
# Deploy with environment variables
gcloud functions deploy oauth-api \
  --runtime nodejs20 \
  --trigger-http \
  --entry-point api \
  --allow-unauthenticated \
  --set-env-vars AUTH0_DOMAIN=your-tenant.auth0.com \
  --set-env-vars AUTH0_AUDIENCE=https://your-api \
  --set-env-vars AUTH0_CLIENT_ID=your-client-id \
  --set-secrets AUTH0_CLIENT_SECRET=auth0-secret:latest \
  --set-env-vars NOONY_GUARD_CACHE_ENABLE=true
```

## Troubleshooting

### Common OAuth Errors

#### "invalid_grant" Error

**Cause**: Authorization code expired or already used.

**Solution**:
- Authorization codes expire quickly (typically 60 seconds)
- Codes can only be used once
- Ensure code exchange happens immediately after redirect

```typescript
// Check code expiration
if (Date.now() - authRequestTime > 60000) {
  throw new Error('Authorization code expired');
}
```

#### "invalid_token" Error

**Cause**: Access token expired or invalid.

**Solution**:
- Implement token refresh logic
- Check token expiration before API calls

```typescript
// Frontend: Auto-refresh tokens
async function getValidToken(): Promise<string> {
  let token = localStorage.getItem('access_token');
  const expiry = localStorage.getItem('token_expiry');

  if (!token || Date.now() >= parseInt(expiry!)) {
    // Refresh token
    const refreshToken = localStorage.getItem('refresh_token');
    const newTokens = await refreshAccessToken(refreshToken!);

    localStorage.setItem('access_token', newTokens.access_token);
    localStorage.setItem('token_expiry', (Date.now() + newTokens.expires_in * 1000).toString());

    token = newTokens.access_token;
  }

  return token;
}
```

#### "insufficient_scope" Error

**Cause**: Token doesn't have required OAuth scopes.

**Solution**:
- Request correct scopes during authorization
- Update scope mapping configuration

```typescript
// Ensure required scopes are requested
const authUrl = flow.getAuthorizationUrl({
  scope: 'openid profile email read:users write:users admin',
  // Not just: 'openid profile email'
});
```

#### JWKS Verification Failed

**Cause**: Token signed with unknown key.

**Solution**:
- Wait for JWKS cache refresh (automatic with jose library)
- Verify token issuer matches expected value
- Check for clock skew

```typescript
// Increase clock tolerance
const { payload } = await jwtVerify(token, jwks, {
  issuer: expectedIssuer,
  audience: expectedAudience,
  clockTolerance: 120, // Allow 2 minutes clock skew
});
```

### Debug Mode

Enable detailed logging for troubleshooting:

```typescript
// Enable OAuth debug logging
export const routeGuards = new RouteGuards({
  ...guardProfile,
  monitoring: {
    enablePerformanceTracking: true,
    enableDetailedLogging: true,
    logLevel: 'debug',
  },
});

// Log all token validations
tokenValidator.onValidation((result) => {
  console.debug('Token Validation:', {
    valid: result.valid,
    provider: result.metadata?.provider,
    cached: result.metadata?.cached,
    error: result.error,
    claims: result.decoded,
  });
});
```

### Performance Optimization

Monitor and optimize OAuth validation:

```typescript
// Check guard performance
const stats = routeGuards.getStats();

console.log('OAuth Guard Performance:', {
  cacheHitRate: `${stats.cacheHitRate.toFixed(2)}%`,
  avgTokenValidation: `${stats.averageResolutionTimeUs.toFixed(1)}μs`,
  totalValidations: stats.authAttempts,
});

// If cache hit rate < 70%, increase cache TTL
if (stats.cacheHitRate < 70) {
  console.warn('⚠️ Low cache hit rate - consider increasing TTL');
}
```

## Additional Resources

- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Core Spec](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [Auth0 Documentation](https://auth0.com/docs)
- [Google OAuth 2.0](https://developers.google.com/identity/protocols/oauth2)
- [Microsoft Identity Platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/)
- [Noony Guard System](./GUARD_SYSTEM.md)
- [Firebase Auth Guide](./firebase-auth-guide.md)

## Support

For issues or questions:

- GitHub Issues: [noony-core/issues](https://github.com/noony-serverless/noony-core/issues)
- Documentation: [noony-core/docs](https://github.com/noony-serverless/noony-core/tree/main/docs)
- Examples: [noony-core/examples](https://github.com/noony-serverless/noony-core/tree/main/examples)
