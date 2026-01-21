# Skill 12: Comprehensive Guard System

## Triggers

When user asks to:
- "Setup authentication"
- "Protect routes"
- "Configure guards"
- "Setup RBAC"

## What it provides

Configuration pattern for `RouteGuards` with `TokenValidator` and `PermissionSource`.

## Complete Example

```typescript
import { RouteGuards, TokenValidator, UserPermissionSource } from '@noony-serverless/core';

// 1. Validator
class JwtValidator implements TokenValidator {
    async validateToken(token: string) { /* verify JWT */ return { valid: true, decoded: { sub: '123' } }; }
    extractUserId(decoded: any) { return decoded.sub; }
    isTokenExpired(decoded: any) { return false; }
}

// 2. Permission Source
class DbPermissions implements UserPermissionSource {
    async getUserPermissions(userId: string) { 
        return { permissions: ['read:data'], roles: ['user'] }; 
    }
    async getRolePermissions(roles: string[]) { return []; } 
    async isUserContextStale() { return false; }
}

// 3. Initialize
const guards = new RouteGuards(new JwtValidator(), new DbPermissions());

// 4. Use in Handler
// .use(guards.requirePermissions(['read:data']))
```

## When to use

- Application startup (singleton initialization)
- Protecting sensitive endpoints
- Managing complex permission logic
