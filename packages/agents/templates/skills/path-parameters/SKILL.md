---
name: noony-path-parameters
description: Activate when handling path parameters, route params, accessing :userId or :id from routes, parsing numeric IDs, UUID validation in routes, or distinguishing path params from query params. Used at position 8 in the canonical middleware order (see `noony-middleware-ordering` skill).
---

# skill:noony-path-parameters

## Does exactly this

Guides you through extracting, typing, and validating path parameters from any framework adapter. Covers simple strings, multiple params, numeric parsing, UUIDs, slugs, and the distinction from query parameters. Path params sit at position 8 in the canonical middleware order (see `noony-middleware-ordering` skill).

## When to use

- Defining routes with `:paramName` syntax
- Accessing path parameters from `context.req.params`
- Parsing numeric or UUID path parameters
- Setting up path params in a custom framework adapter
- Distinguishing path params from query params

## Do not use this skill when

- You need query string parameter handling -> see `noony-validation-schemas` skill for query validation
- You are parsing the request body -> see `noony-validation-schemas` skill for body validation
- You need to decide WHERE to place path params middleware in the chain -> see `noony-middleware-ordering` skill, it is the authority
- You need middleware ordering guidance -> see `noony-middleware-ordering` skill

## Steps

1. **Define a TypeScript interface** for all path parameters in the route
   - Each parameter is always a `string` at the framework level
   - Parse to `number`, UUID, etc. after extraction
   -> references/path-parameters.md

2. **Register the route** with `:paramName` syntax in your framework
   - Fastify: `server.get('/users/:userId/posts/:postId', handler)`
   - Custom adapters must map `params` to `GenericRequest.params`
   -> references/path-parameters.md

3. **Access params** via `context.req.params`
   - Cast to your interface type for type safety
   - Never read path params from `context.req.body` or `context.req.query`

4. **Validate format** before using the parameter value
   - Numeric: parse with `parseInt()` or `Number()`, check `isNaN()`
   - UUID: validate with regex or a library before database lookups
   - Slug: validate against allowed characters

5. **Verify path params middleware is at position 8** per `noony-middleware-ordering` skill — after body parsing/validation (positions 6-7) and before auth guards (positions 9-12)

6. **In custom adapters**, ensure `params` is mapped in the `GenericRequest` adapter
   - The `params` property must be `Record<string, string>`
   - See the custom adapter guide for the full property table
   -> references/path-parameters.md

## Rules

- Path params are **always strings** — parse to the target type explicitly
- Access via `context.req.params` only — never from body or query
- Define a TypeScript interface matching all route parameters
- Validate format and type before using (UUID, numeric, slug)
- Multiple parameters use separate `:param` declarations in the route path
- Custom adapters must include `params` in the `GenericRequest` mapping
- `noony-guard-system` skill depends on path params for ownership checks — set up path params (position 8) before guards (positions 9-12) per `noony-middleware-ordering` skill

## Anti-patterns

- Accessing path params from `context.req.body` — they live in `params`, not body
- Forgetting `:paramName` syntax in route definition — becomes a literal path segment
- Casting to `number` without validation — `Number("abc")` returns `NaN` silently
- Confusing path params (`/users/:id`) with query params (`/users?id=123`)
- No TypeScript interface for params — loses type safety across the handler
- Custom adapter missing `params` property — path parameters become `undefined`
- Placing path params middleware after auth guards — guards that need `:userId` for ownership checks will fail

## Done when

- Path param interface is defined with correct types
- Params are extracted from `context.req.params` (not body or query)
- Numeric and UUID parameters are validated before use
- Path params middleware is at position 8 per `noony-middleware-ordering` skill
- Custom adapter (if applicable) maps `params` to `GenericRequest`

## If you need more detail

-> references/path-parameters.md — Complete patterns for simple, multiple, type-safe, numeric, UUID, and slug parameters with testing examples and common mistake fixes
