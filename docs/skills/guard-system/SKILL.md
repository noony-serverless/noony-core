---
name: guard-system
description: Use when implementing authorization, restricting endpoints by permissions, setting up role-based access control (RBAC), checking user permissions, configuring RouteGuards, using GuardSetup presets, implementing ownership-based or team-based access, or adding wildcard/complex permission expressions in Noony handlers.
---

# skill:guard-system

## Does exactly this

RouteGuards for authorization: three protection methods (simple, wildcard, complex), GuardSetup presets for environment configuration, permission ordering rules, and RBAC patterns including ownership checks.

## When to use

- "Restrict endpoint to specific permissions"
- "Role-based access control (RBAC)"
- "Ownership-based or team-based access"
- "GuardSetup production vs development"
- "Simple vs wildcard vs complex permission checks"
- "Permission guards after authentication"

## Do not use this skill when

- For authentication SETUP (token verification) → see AuthenticationMiddleware docs
- For error handling in guards (403 responses) → use `error-handling`
- For middleware ordering of guards in the pipeline → use `middleware-ordering`
- For DI in guard middleware → use `dependency-injection`
- For testing guard authorization → use `testing-handlers`

## Prerequisites

Guards require:
- **AuthenticationMiddleware** must run first (sets `context.user`)
- **Path parameters extracted** (`path-parameters`) before guards that check resource ownership
- **Correct middleware ordering** per `middleware-ordering`'s canonical order

## Steps

1. Configure guards once at startup with `GuardSetup.production()` or `GuardSetup.development()`
   → See `references/guard-patterns.md#guardsetup-presets` for environment presets

2. Place guards AFTER `AuthenticationMiddleware` per `middleware-ordering`'s canonical order — user must exist before checking permissions
   - Canonical: ErrorHandler → OTel → Auth → Guards → BodyParser → Validation → ...

3. Ensure path parameters are extracted (`path-parameters`) before guards that check resource ownership
   - Ownership guards need `context.req.params.id` to verify the user owns the resource

4. Use `RouteGuards.requirePermissions()` for simple permission checks (most common)
   → See `references/guard-patterns.md#requirepermissions-simple-checks` for examples

5. Use `RouteGuards.requireWildcardPermissions()` for hierarchical patterns like `admin:*`
   → See `references/guard-patterns.md#requirewildcardpermissions-pattern-matching` for wildcard syntax

6. Use inline `before()` middleware for complex ownership/team-based checks that need DB lookups
   → See `references/guard-patterns.md#complex-authorization-ownership-teams` for patterns

7. Test guard authorization with mock users and permission arrays
   → See `testing-handlers` for guard testing examples

## Rules

- `AuthenticationMiddleware` MUST run before guards — guards need `context.user` populated
- Guards check `context.user.permissions` array for required permissions
- `GuardSetup` configured ONCE at startup — never per-request
- Middleware ordering: ErrorHandler → Auth → Guards → business logic (see `middleware-ordering`)
- Use simple permissions for most cases — wildcards add matching overhead
- Permission naming convention: `resource:action` (e.g., `posts:create`, `admin:*`)
- 403 Forbidden returned when authenticated but lacking permissions (see `error-handling`)

## Anti-patterns

- ❌ Guards before `AuthenticationMiddleware` — `context.user` not populated yet, always fails
- ❌ `GuardSetup.production()` inside request handler — initialization latency per request
- ❌ Complex wildcard expressions when simple permissions suffice — unnecessary overhead
- ❌ Hardcoding role checks in handler body instead of using guards — scatters authorization logic
- ❌ Same permissions for all endpoints — no granularity, defeats purpose of RBAC
- ❌ Inconsistent permission naming (`admin-read` vs `admin:read`) — wildcards won't match dashes
- ❌ Ownership guards without path parameter extraction — `context.req.params` is empty

## Done when

- You know the difference between authentication (who) and authorization (what)
- Guards placed after `AuthenticationMiddleware` in the pipeline
- Path parameters available before ownership guards
- Simple permission checks working with `requirePermissions()`
- You understand the three protection methods and when to use each

## If you need more detail

→ `references/guard-patterns.md` — GuardSetup presets, three protection methods with code, RBAC patterns, ownership/team-based access, multi-route setup, testing guards, common gotchas
