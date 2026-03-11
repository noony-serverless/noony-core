# Skill 04: Path Parameters with Fastify

## Does exactly this

Provides 7 patterns for handling path parameters: simple strings, multiple params, type-safe extraction, numeric parsing, UUIDs, slugs, and distinguishing from query parameters.

## When to use

- "Handle path parameters"
- "Access :userId from route"
- "Multiple path parameters"
- "Parse numeric IDs"
- "UUID validation in routes"

## Steps

1. Define TypeScript interface for all path params in the route
2. Access via `context.req.params` — cast to your interface type
3. Validate parameter format if needed (UUID, numeric, slug format)
4. Never access path params from body — they're in context.req.params only
   → See resources/04-path-parameters.md#pattern-1-simple-string-path-parameter for code

## Rules

- Path parameters MUST be declared in Fastify route with `:paramName` syntax
- Always access via `context.req.params` — never from body or query
- Define TypeScript interface matching all parameters for type safety
- Validate parameter format/type before using (UUID, numeric, etc.)
- Path params are strings — parse to number/UUID/other types when needed
- Multiple parameters use separate `:param` declarations, e.g., `/users/:userId/posts/:postId`

## Anti-patterns

- ❌ Accessing path params from `context.req.body` — they're in params, not body
- ❌ Forgetting `:paramName` syntax in Fastify route — becomes literal path part, not parameter
- ❌ Not validating numeric/UUID parameters — type casting doesn't validate format
- ❌ Confusing path params with query parameters (different access, different semantics)
- ❌ No TypeScript interface for params — loses type safety

## Done when

- You can define TypeScript interface for path params
- You understand how to extract params from context.req.params
- You know how to validate numeric and UUID parameters
- You can distinguish path params from query parameters

## If you need more detail

→ resources/04-path-parameters.md — 7 complete patterns (simple, multiple, type-safe, numeric, UUID, slug, vs query), common mistakes with fixes, testing examples
