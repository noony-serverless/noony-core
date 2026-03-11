# Skill 09: Validation Schemas with Zod

## Does exactly this

Provides Zod integration patterns: schema definition, parsedBody vs validatedBody access, BodyParserMiddleware ordering, and Pub/Sub validation flow.

## When to use

- "Validate request body"
- "Use Zod schema"
- "How to test validation"
- "Pub/Sub message validation"

## Steps

1. Define Zod schema and infer TypeScript type via `z.infer<typeof schema>`
   → See resources/09-validation-patterns.md#pattern-1-basic-schema for code
2. Always use `BodyParserMiddleware` BEFORE `BodyValidationMiddleware` to parse body first
3. In handler, access validated data via `context.req.validatedBody!` (not body)
4. For Pub/Sub, use `isPubSubMessage()` guard to detect message type, then parse
   → See resources/09-validation-patterns.md#pattern-4-pubsub-message-validation

## Rules

- Never access `context.req.body` directly — use validatedBody after validation middleware
- Always use `z.infer<typeof schema>` for TypeScript types — don't define interface separately
- BodyParserMiddleware MUST come before BodyValidationMiddleware in middleware chain
- Async validation supported via `schema.parseAsync()` — use for database lookups
- ValidationError (400) thrown automatically for invalid data — no manual error handling needed

## Anti-patterns

- ❌ Accessing `context.req.body` directly without validation — unsafe, untyped
- ❌ Skipping BodyParserMiddleware — base64 Pub/Sub messages not decoded
- ❌ Defining TypeScript interface separately from Zod schema — duplicates type
- ❌ Validating in handler instead of middleware — defeats middleware benefits
- ❌ Using `context.req.parsedBody` after BodyValidationMiddleware — use validatedBody instead

## Done when

- You can define Zod schema and infer types
- You understand parsedBody vs validatedBody
- You know middleware ordering (parser before validator)
- You can validate Pub/Sub messages

## If you need more detail

→ resources/09-validation-patterns.md — 6 patterns (basic, arrays, enums, async, custom, Pub/Sub), parsedBody vs validatedBody, error handling, testing examples, performance, anti-patterns
