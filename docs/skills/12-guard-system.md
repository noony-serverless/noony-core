# Skill 12: Comprehensive Guard System

## Does exactly this

Covers RouteGuards for RBAC (role-based access control): requirePermissions for simple checks, three protection methods, GuardSetup presets, and ordering rules.

## When to use

- "Restrict endpoint to admins"
- "Check user permissions"
- "Role-based access control"
- "Ownership-based access"

## Steps

1. Use `GuardSetup.production()` or `GuardSetup.development()` presets to configure guards
2. Add guard after AuthenticationMiddleware (user must exist first)
3. Use `RouteGuards.requirePermissions()` for simple permission checks
4. For complex logic, use `requireWildcardPermissions()` or `requireComplexPermissions()`
   → See resources/12-guard-patterns.md#three-protection-methods for each approach

## Rules

- AuthenticationMiddleware MUST run before guards — user is required
- Guards check `context.user.permissions` array for required permissions
- Use simple permissions (e.g., `'admin'`, `'write'`) for most cases
- GuardSetup configured ONCE at startup — never per-request
- Middleware ordering: ErrorHandler → Auth → Guards → business logic

## Anti-patterns

- ❌ Using RouteGuards instead of AuthenticationMiddleware for token validation — guards check permissions, not auth
- ❌ RouteGuards.configure() inside request handler — initialization latency
- ❌ Complex wildcard expressions when simple permissions work — unnecessary performance cost
- ❌ Guards before AuthenticationMiddleware — user context not populated yet
- ❌ Same permissions for all endpoints — no granularity, all-or-nothing access

## Done when

- You know difference between authentication (who are you) and authorization (what can you do)
- You can set up simple permission checks
- You know middleware ordering rule (Auth before Guards)
- You understand three protection methods

## If you need more detail

→ resources/12-guard-patterns.md — GuardSetup presets, three protection methods (simple, wildcard, complex), RBAC patterns, owner-based and team-based access, multi-route setup, testing guard authorization, common gotchas
