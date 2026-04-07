---
description: Noony type safety rules. Apply whenever creating handlers, writing middleware, or working with generics in a Noony project.
globs:
  - "src/**/*.ts"
  - "functions.ts"
alwaysApply: false
---

# Noony — Type Safety Rules

## The Type Chain

`<TBody, TUser>` MUST flow through every layer: `Handler<TBody, TUser>` → middleware → `Context<TBody, TUser>`.

If any layer drops the generics, types degrade to `unknown` downstream.

## Custom Middleware Must Preserve Generics

```typescript
// WRONG — breaks type chain
class MyMiddleware implements BaseMiddleware { ... }

// CORRECT
class MyMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser> {
  async before(context: Context<TBody, TUser>) { ... }
}
```

## Rules

- Never use `as any` — find and fix the missing generic instead
- `context.req.validatedBody` typed as `unknown` → Handler or BodyValidationMiddleware missing `TBody`
- `context.user` typed as `unknown` → Handler missing `TUser` or auth middleware not typed
- Do not mix explicit generics and `createTypedHandler()` in the same chain
- `BaseMiddleware` without `<TBody, TUser>` → type chain broken at that middleware

## Forbidden

```typescript
as any
as unknown as SomeType
Handler<unknown, unknown>  // when you have actual types
```

## Reference

→ `docs/noony-skills/type-inference/SKILL.md`
