---
description: Noony type safety rules — apply when creating handlers, writing middleware, or working with generics.
globs: ["src/**/*.ts", "functions.ts"]
---

# Noony — Type Safety Rules

`<TBody, TUser>` MUST flow through every layer: `Handler<TBody, TUser>` → all middleware → `Context<TBody, TUser>`.

Custom middleware must preserve generics:

```typescript
class MyMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser> {
  async before(context: Context<TBody, TUser>) { ... }
}
```

- Never use `as any` — find the missing generic
- `validatedBody` typed as `unknown` → Handler or BodyValidationMiddleware missing `TBody`
- `context.user` typed as `unknown` → Handler missing `TUser`
- `BaseMiddleware` without generics → type chain broken

Forbidden: `as any` · `Handler<unknown, unknown>` when you have types · mixing explicit generics with `createTypedHandler()`.
