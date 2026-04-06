---
name: noony-validation-schemas
description: Use when validating request bodies with Zod schemas, understanding parsedBody vs validatedBody, ordering BodyParserMiddleware before BodyValidationMiddleware, handling Pub/Sub message validation, defining async validation, or inferring TypeScript types from Zod schemas in Noony handlers.
---

# skill:noony-validation-schemas

## Does exactly this

Provides Zod integration patterns for Noony: schema definition with `z.infer`, the parsedBody-to-validatedBody pipeline, middleware ordering per `noony-middleware-ordering`, Pub/Sub message validation, and async validation with database lookups.

## When to use

- "Validate request body"
- "Use Zod schema"
- "parsedBody vs validatedBody"
- "Pub/Sub message validation"
- "Async validation with database lookup"
- "How to test validation"

## Do not use this skill when

- You need error class selection -> `noony-error-handling` for error types and cause chaining
- You need middleware ordering beyond validation -> `noony-middleware-ordering` is the canonical reference
- You need custom middleware development -> `noony-middleware-development`
- You need path parameter validation -> `noony-path-parameters` handles route params
- You need type inference guidance -> `noony-type-inference` for generics flow

## Steps

1. Define Zod schema and infer TypeScript type via `z.infer<typeof schema>` — never define a separate interface
   -> See `references/validation-patterns.md#basic-object-schema` for code
2. **Verify middleware ordering per `noony-middleware-ordering`**: ErrorHandlerMiddleware (position 1) -> BodyParserMiddleware (position 6) -> BodyValidationMiddleware (position 7) — parser converts raw body to `parsedBody`, validator checks `parsedBody` against schema and populates `validatedBody`
   -> See `references/validation-patterns.md#middleware-order` for the pipeline
3. Pass the inferred type to Handler: `new Handler<CreateUserRequest, AuthUser>()` — using `unknown` makes `validatedBody` untyped
4. In handler, access validated data via `context.req.validatedBody!` (not `body` or `parsedBody`)
5. For Pub/Sub messages, validate the envelope first (base64 decode via transform), then validate the decoded content with a second schema
   -> See `references/validation-patterns.md#pubsub-message-validation`
6. For async validation (database lookups), add `{ async: true }` option to `BodyValidationMiddleware`
   -> See `references/validation-patterns.md#async-validation`

## Rules

- Never access `context.req.body` directly — always use `validatedBody` after validation middleware
- Always use `z.infer<typeof schema>` for TypeScript types — single source of truth, no interface drift
- `BodyParserMiddleware` MUST come before `BodyValidationMiddleware` — positions 6 and 7 in the canonical order (see `noony-middleware-ordering`)
- `ErrorHandlerMiddleware` MUST be present at position 1 (see `noony-middleware-ordering`) — without it, `ValidationError` crashes the function instead of returning a clean 400
- Async validation requires `{ async: true }` option — without it, async refinements silently break
- Define schemas at module scope, not inside handlers — schema compilation happens once
- Place expensive `.refine()` checks last — cheap format checks fail first for better performance

## Anti-patterns

- Accessing `context.req.body` directly — unsafe, untyped, bypasses the validation pipeline
- Skipping `BodyParserMiddleware` — `parsedBody` will be undefined, validation has nothing to work with
- Forgetting `BodyParserMiddleware` before `BodyValidationMiddleware` — positions 6 then 7 per `noony-middleware-ordering`; reversing them breaks the pipeline
- Defining TypeScript interface separately from Zod schema — duplicates type definition, can drift out of sync
- Validating inside the handler (`schema.safeParse(body)`) — defeats middleware pipeline benefits, duplicates error handling
- Using `context.req.parsedBody` after `BodyValidationMiddleware` — use `validatedBody` which is type-safe
- `Handler<unknown>` with validation — `validatedBody` stays typed as `unknown` even after validation
- Missing `ErrorHandlerMiddleware` — `ValidationError` crashes the function instead of returning structured 400 JSON

## Done when

- You can define Zod schemas and infer types with `z.infer`
- You understand the parsedBody -> validatedBody pipeline
- You know middleware ordering per `noony-middleware-ordering`: ErrorHandler (1) -> BodyParser (6) -> BodyValidation (7)
- You can validate Pub/Sub messages (envelope + decoded content)
- You know when and how to use async validation

## If you need more detail

-> `references/validation-patterns.md` — Middleware pipeline, schema patterns (basic, nested, arrays, enums, custom refinements), Pub/Sub validation, async validation, error response format, testing examples
