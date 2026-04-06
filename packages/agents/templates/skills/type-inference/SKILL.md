---
name: noony-type-inference
description: Activate when reducing type boilerplate, avoiding repeated generics, inferring types from controller signatures, using createTypedHandler(), choosing between explicit generics and type inference, or fixing broken type chains in middleware.
---

# skill:noony-type-inference

## Does exactly this

Guides you through the two approaches to typed handlers in Noony: explicit generics (`new Handler<TBody, TUser>()`) and automatic inference via `createTypedHandler()`. Both provide full compile-time type safety — choose based on verbosity preference. Type chain preservation is most critical when writing custom middleware (`noony-middleware-development` skill).

## When to use

- Creating a new handler and choosing a typing approach
- Reducing generic boilerplate on middlewares
- Fixing type errors where `validatedBody` or `user` is `unknown`
- Writing custom middleware that preserves the type chain
- Sharing types across multiple handlers

## Do not use this skill when

- You need Zod schema types -> see `noony-validation-schemas` skill, it handles those automatically via `z.infer`
- You need to create a custom middleware -> see `noony-middleware-development` skill for implementation patterns
- You need DI or container services -> see `noony-dependency-initialization` skill
- You need middleware ordering -> see `noony-middleware-ordering` skill

## Steps

1. **Define request schema and user type** — required for both approaches
   - Use `z.infer<typeof schema>` for body types derived from Zod
   - Define a `TUser` interface for authenticated user shape
   -> references/type-inference.md

2. **Choose your approach** based on team preference:
   - **Explicit generics:** `new Handler<TBody, TUser>()` with generics on every middleware
   - **Type inference:** `createTypedHandler(controller)` with typed controller signature
   -> references/type-inference.md

3. **For explicit generics**, pass `<TBody, TUser>` to Handler and every middleware
   - Every `.use(new Middleware<TBody, TUser>())` must include both generics
   - Controller parameter must be `Context<TBody, TUser>`
   -> references/type-inference.md

4. **For type inference**, annotate the controller with `Context<TBody, TUser>` explicitly
   - `createTypedHandler()` infers types from the controller signature
   - Middlewares do not need explicit generics — they are inferred
   - Controller must have an explicit type annotation (not implicit `any`)
   -> references/type-inference.md

5. **Preserve the type chain in custom middleware** — this is where type inference most commonly breaks
   - Always implement `BaseMiddleware<TBody, TUser>` with both generic parameters
   - Use default values `= unknown` on generics for flexibility
   - Missing generics on middleware breaks the chain — `validatedBody` becomes `unknown`
   - If writing custom middleware, apply `noony-middleware-development` skill after this one for implementation patterns
   -> references/type-inference.md

## Rules

- Both approaches provide **full compile-time type safety** — neither is "less safe"
- Never use `as any` to bypass type errors — use proper type declarations
- All middlewares **must** implement `BaseMiddleware<TBody, TUser>` with both generics
- Pick one approach per handler — do not mix explicit and inferred in the same chain
- Controller **must** have explicit `Context<TBody, TUser>` annotation when using `createTypedHandler()`
- Use `= unknown` defaults on custom middleware generics for flexible usage

## Anti-patterns

- `as any` cast to bypass type errors — defeats the entire type system
- Mixing explicit generics on Handler with implicit middlewares — unclear which is authoritative
- Using `createTypedHandler()` with untyped controller — inference fails, types degrade to `unknown`
- Middleware without generics (`BaseMiddleware` instead of `BaseMiddleware<TBody, TUser>`) — breaks type chain; see `noony-middleware-development` skill for correct middleware patterns
- Using `Handler<unknown>` with body validation — `validatedBody` stays `unknown` instead of the schema type
- `Handler<any, any>` cast to a typed handler — bypasses all checking

## Done when

- Handler uses one consistent approach (explicit or inferred) throughout
- `context.req.validatedBody` resolves to `TBody` (not `unknown` or `any`)
- `context.user` resolves to `TUser` (not `unknown` or `any`)
- Custom middlewares implement `BaseMiddleware<TBody, TUser>` with both generics
- No `as any` casts anywhere in the handler chain

## If you need more detail

-> references/type-inference.md — Detailed comparison table, both approaches side by side, multi-handler type sharing patterns, custom middleware type chain preservation, and common gotchas with solutions
