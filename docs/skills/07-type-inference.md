# Skill 07: Type Inference with createTypedHandler()

## Does exactly this

Two approaches to typed handlers: explicit generics (clear, verbose) or automatic inference from controller signature (clean, minimal boilerplate). Both are fully type-safe at compile time.

## When to use

- "Reduce type boilerplate"
- "Avoid repeating generics"
- "Infer types from controller"
- "Simplify handler types"

## Steps

1. Define request schema and user type (required for both approaches)
2. Choose approach based on code clarity preference:
   - **Explicit generics**: `new Handler<TBody, TUser>()` with explicit types on all middlewares
   - **Inference**: `createTypedHandler(controller)` with explicit type on controller
   → See resources/07-type-inference.md#option-1-explicit-generics and #option-2-type-inference for comparison
3. Ensure all middlewares implement `BaseMiddleware<TBody, TUser>` with both generics (type chain preservation)
4. Never use `as any` to bypass type checking — use proper type declarations instead

## Rules

- Both explicit generics and type inference provide full compile-time type safety
- Never `as any` cast on handlers — defeats type system entirely
- All middlewares MUST implement `BaseMiddleware<TBody, TUser>` with both generics
- Pick one approach and use consistently across handlers — don't mix explicit and inference in same handler
- Controller must have explicit `Context<TBody, TUser>` type annotation when using `createTypedHandler()`

## Anti-patterns

- ❌ `as any` cast to bypass type errors — loses all type checking, defeats purpose
- ❌ Mixing explicit generics and type inference in same handler — confuses readers about which is authoritative
- ❌ Using `createTypedHandler()` with untyped controller — inference fails, types lost
- ❌ Middlewares without generics (e.g., `BaseMiddleware` instead of `BaseMiddleware<TBody, TUser>`) — breaks type chain
- ❌ Repeating type generics on every middleware when using explicit approach — verbose but unavoidable with this approach

## Done when

- You understand when to use explicit generics vs type inference
- You know both approaches provide full type safety
- You can avoid `as any` by using proper type declarations
- You recognize when type chain is broken (missing generics on middleware)

## If you need more detail

→ resources/07-type-inference.md — Detailed examples of both approaches, comparison table, advanced multi-handler patterns, common gotchas with solutions, type chain preservation, when to use each approach
