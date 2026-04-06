# Uncle Noony — Workflow Reference

## Skill Relationship Diagram

```
                         ┌──────────────────────┐
                         │   00 noony-uncle-noony      │
                         │   (orchestrator)      │
                         └──────────┬─────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          │                         │                         │
          v                         v                         v
 ┌─────────────────┐    ┌─────────────────┐     ┌──────────────────┐
 │ FRAMEWORK SETUP │    │  REQUEST PIPELINE│     │   QUALITY        │
 │                 │    │                  │     │                  │
 │  01 fastify     │    │  04 path-params  │     │  14 testing      │
 │  02 convert     │    │  09 validation   │     │                  │
 │  03 adapter     │    │  10 errors       │     └──────────────────┘
 │  06 dual-entry  │    │  17 ordering     │
 └─────────────────┘    └─────────────────┘
          │                         │
          v                         v
 ┌─────────────────┐    ┌─────────────────┐
 │   TYPE SAFETY   │    │   DATA & AUTH   │
 │                 │    │                 │
 │  07 inference   │    │  05 init        │
 │  08 middleware   │    │  11 DI          │
 │     dev         │    │  12 guards      │
 └─────────────────┘    │  13 performance │
                        └─────────────────┘
```

### Cluster Summary

| Cluster | Skills | Covers |
|---------|--------|--------|
| **Framework Setup** | 01, 02, 03, 06 | Local dev, migration, adapters, dual-entry |
| **Type Safety** | 07, 08 | Generic inference, custom middleware types |
| **Request Pipeline** | 04, 09, 10, 17 | Path params, validation, errors, ordering |
| **Data & Auth** | 05, 11, 12, 13 | Initialization, DI, guards, performance |
| **Quality** | 14 | Testing patterns |

---

## Journey Details

### New Project Journey (Apply 01, then 05, then 06, then 17, then 10)

For developers starting from scratch with the Noony framework.

**Step 1 — Apply skill 01: Local dev environment**
Set up a Fastify server for local development. This gives you hot-reload and a real HTTP server to test against, instead of deploying to GCP every time.

**Step 2 — Apply skill 05: Initialize services**
Set up the singleton initialization guard. This ensures your database connections, external clients, and shared services are initialized exactly once — critical for serverless cold starts.

**Step 3 — Apply skill 06: Dual-entry pattern**
Wire up the complete dual-entry: same handler code runs both locally (Fastify) and in production (Cloud Functions). Zero code duplication.

**Step 4 — Apply skill 17: Middleware ordering**
Learn the canonical middleware order. This is the #1 source of bugs for new developers — getting this wrong means errors don't get caught, auth runs before body parsing, or validation happens too late.

**Step 5 — Apply skill 10: Error handling**
Set up `ErrorHandlerMiddleware` and learn the error class hierarchy. Every handler needs this.

---

### New Endpoint Journey (Apply 17, then 09, then 10, then optionally 08)

For developers adding a new API endpoint to an existing Noony project.

**Step 1 — Apply skill 17: Middleware chain**
Start with the canonical middleware order for your endpoint type. CRUD endpoint? Auth endpoint? Read-only? The ordering table has recipes for each.

**Step 2 — Apply skill 09: Validation**
Define your Zod schema for the request body. This gives you automatic TypeScript types AND runtime validation — `context.req.validatedBody` is fully typed.

**Step 3 — Apply skill 10: Error handling**
Pick the right error classes for your endpoint's failure modes. 404 for missing resources, 409 for duplicates, 403 for permission denied. Let `ErrorHandlerMiddleware` format them.

**Step 4 (if needed) — Apply skill 08: Custom middleware**
Only if your endpoint needs custom cross-cutting logic (rate limiting, audit logging, data transformation). Most endpoints don't need this.

---

### Path Parameters Journey (Apply 04, then combine with 09 or 12)

For developers handling dynamic route segments like `/users/:userId/posts/:postId`.

**Step 1 — Apply skill 04: Path parameter extraction**
Set up parameter extraction middleware to populate `context.req.params`. Covers single params, nested params, and type coercion.

**Step 2 — Combine with other skills as needed:**
- Need to validate the param format? Apply skill 09 (Zod can validate params too).
- Need ownership-based auth (e.g., "user can only edit own posts")? Apply skill 12 (guards can reference params).
- Building a CRUD endpoint? Apply skill 17 to get the full ordering with params included.

---

### Add Auth Journey (Apply 12, then 17)

For developers adding authentication and authorization to existing handlers.

**Prerequisite check:** Does the handler already have `ErrorHandlerMiddleware`? If not, apply skill 10 first — auth errors (401, 403) need the error handler to format them.

**Step 1 — Apply skill 12: Guard system**
Choose your auth strategy: simple permission checks, wildcard patterns, or complex ownership-based rules. Set up `RouteGuards` with `GuardSetup` presets.

**Step 2 — Apply skill 17: Middleware ordering**
Auth middleware must come after body parsing and parameter extraction (because guards may need to check resource ownership from the URL). Verify your chain follows the canonical order.

---

### Performance Journey (Apply 13, then 11)

For developers optimizing cold starts or memory usage.

**Note on skill 05 vs 13:** Skill 05 teaches the initialization HOW-TO (singleton guard pattern). Skill 13 covers broader performance optimization including that same pattern plus container pool, zero-copy DI, and memory analysis. For performance work, start with skill 13 — it absorbs skill 05's initialization pattern in a performance context.

**Step 1 — Apply skill 13: Performance optimization**
Implement container pool and the singleton initialization guard. Move heavy initialization (DB connections, SDK clients) to process-level scope so they survive across warm invocations. Analyze memory usage with the zero-copy pattern.

**Step 2 — Apply skill 11: DI patterns**
Use the hybrid proxy container for zero-copy DI. Global services (DB, logger) are shared across requests; request-scoped data (user, trace ID) gets its own local scope.

---

### Service Resolution Journey (Apply 11, then 13 for optimization)

For developers setting up dependency injection and service resolution.

**Step 1 — Apply skill 11: DI patterns**
Set up TypeDI container with `getService()` helper. Configure global vs request-scoped services. Understand the hybrid proxy container pattern.

**Step 2 (optional) — Apply skill 13: Optimize service initialization**
If services are heavy (DB connections, SDK clients), apply the container pool pattern from skill 13 to share them across invocations and reduce cold start time.

---

### Local Dev Journey (Apply 01, then 02, then 06)

For developers setting up or migrating to local Fastify development.

**Step 1 — Apply skill 01: Create Fastify server**
Minimal server setup with `createFastifyHandler()`.

**Step 2 — Apply skill 02: Convert existing handlers**
If you have existing Cloud Functions handlers, convert them to the dual-entry pattern without changing business logic.

**Step 3 — Apply skill 06: Complete example**
Wire up the full project structure: handler module, init module, Fastify entry, Cloud Functions entry.

---

### Validation Journey (Apply 09, then 17)

For developers adding request validation to endpoints.

**Step 1 — Apply skill 09: Zod schemas**
Define schemas for body, query, and params. Get automatic TypeScript type inference from your runtime validation.

**Step 2 — Apply skill 17: Middleware ordering**
Ensure `BodyValidationMiddleware` is positioned after `BodyParserMiddleware` in the chain.

---

### Custom Middleware Journey (Apply 08, then 17)

For developers building reusable middleware.

**Step 1 — Apply skill 08: Middleware development**
Implement `BaseMiddleware<TBody, TUser>` with before/after/onError hooks. Preserve generics throughout.

**Step 2 — Apply skill 17: Middleware ordering**
Place your custom middleware at the correct position in the canonical order.

---

### Testing Journey (Apply 14)

For developers writing tests for their handlers.

**Single skill** — skill 14 covers all 4 testing patterns:
1. Full handler chain testing (integration)
2. Middleware in isolation (unit)
3. DI service mocking (unit with mocks)
4. Error path testing (verify error types and status codes)

---

### Type Issues Journey (Apply 07, then 08)

For developers whose TypeScript types are breaking or not inferring correctly.

**Step 1 — Apply skill 07: Type inference**
Understand the two approaches: explicit generics `Handler<TBody, TUser>` vs `createTypedHandler()`. Pick the right one for your situation.

**Step 2 — Apply skill 08: Middleware types**
If types break in custom middleware, it's almost always because generics aren't preserved. Every middleware must `implement BaseMiddleware<TBody, TUser>` with both type parameters.

---

## Verification Checklist

After applying skills, verify the handler meets these criteria:

### Structure
- [ ] `ErrorHandlerMiddleware` is the **first** middleware in the chain
- [ ] Middleware follows canonical ordering (skill 17)
- [ ] Handler uses `<TBody, TUser>` generics consistently
- [ ] No code duplication between entry points

### Error Handling
- [ ] All error paths throw typed errors (not generic `Error()`)
- [ ] External API calls use cause chaining
- [ ] No manual `res.status().json()` — errors thrown, not returned

### Type Safety
- [ ] `context.req.validatedBody` is typed (not `unknown`)
- [ ] `context.user` is typed (not `unknown`)
- [ ] Custom middleware preserves `<TBody, TUser>` generics
- [ ] No `as any` casts

### DI & Initialization
- [ ] Global services use singleton guard pattern
- [ ] Request-scoped data uses local container scope
- [ ] Services accessed via `getService()` helper

### Testing
- [ ] At least one test per error path
- [ ] Middleware chain tested as a unit
- [ ] DI services properly mocked

---

## Production-Ready Handler Template

A complete handler showing path params, auth, validation, and DI:

```typescript
import { Handler, ErrorHandlerMiddleware, BodyParserMiddleware,
  BodyValidationMiddleware, AuthenticationMiddleware,
  ResponseWrapperMiddleware, DependencyInjectionMiddleware,
  PathParameterMiddleware
} from '@noony-serverless/core';
import { z } from 'zod';

// 1. Define your types with Zod (skill 09)
const UpdateUserSchema = z.object({
  name: z.string().min(1).max(100),
  role: z.enum(['user', 'admin']),
});
type UpdateUserRequest = z.infer<typeof UpdateUserSchema>;

// 2. Define your user type (skill 12)
interface AuthUser {
  id: string;
  email: string;
  roles: string[];
}

// 3. Build the handler with canonical middleware order (skill 17)
//    Path: PUT /users/:userId
export const updateUserHandler = new Handler<UpdateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())                          // Position 1: catches all errors
  .use(new DependencyInjectionMiddleware(globalServices))     // Position 2: services available
  .use(new PathParameterMiddleware())                         // Position 3: extract :userId (skill 04)
  .use(new BodyParserMiddleware())                            // Position 6: parse body
  .use(new BodyValidationMiddleware(UpdateUserSchema))        // Position 7: validate body
  .use(new AuthenticationMiddleware(tokenVerifier))           // Position 8: verify auth
  .use(new ResponseWrapperMiddleware())                       // Position last: wrap response
  .handle(async (context) => {
    const userId = context.req.params.userId;                  // From path params (skill 04)
    const { name, role } = context.req.validatedBody!;         // Fully typed (skill 09)
    const currentUser = context.user!;                         // Fully typed (skill 12)

    // 4. Use typed errors (skill 10)
    if (!currentUser.roles.includes('admin') && currentUser.id !== userId) {
      throw new ForbiddenError('Can only update own profile or must be admin');
    }

    const existing = await getService(UserService).findById(userId);
    if (!existing) {
      throw new NotFoundError(`User ${userId} not found`);
    }

    // 5. Cause chain external errors (skill 10)
    try {
      const user = await getService(UserService).update(userId, { name, role });
      return { userId: user.id, name: user.name, role: user.role };
    } catch (err) {
      throw new InternalServerError('Failed to update user', err as Error);
    }
  });
```

---

## "I'm Stuck" — Common Scenarios

### "My handler returns 500 for everything"

**Likely cause**: `ErrorHandlerMiddleware` is missing or not first.
**Fix**: Add `.use(new ErrorHandlerMiddleware())` as the very first middleware.
Apply skill 10 + skill 17.

### "TypeScript says my validatedBody is `unknown`"

**Likely cause**: Missing generics on `Handler` or `BodyValidationMiddleware`.
**Fix**: Use `new Handler<MySchema, MyUser>()` and `new BodyValidationMiddleware<MySchema, MyUser>(schema)`.
Apply skill 07 + skill 09.

### "Auth middleware runs but context.user is undefined"

**Likely cause**: `AuthenticationMiddleware` is before `BodyParserMiddleware` in the chain.
**Fix**: Follow canonical ordering — auth comes after body parsing and parameter extraction.
Apply skill 12 + skill 17.

### "Path params are undefined in my controller"

**Likely cause**: `PathParameterMiddleware` is missing or positioned incorrectly.
**Fix**: Add `PathParameterMiddleware` early in the chain (after DI, before body parsing).
Apply skill 04 + skill 17.

### "Cold starts are taking 3+ seconds"

**Likely cause**: Services initialized inside the handler instead of at process level.
**Fix**: Use container pool with singleton initialization guard.
Apply skill 13 (covers the initialization pattern from skill 05).

### "My custom middleware breaks the type chain"

**Likely cause**: Missing generics on `implements BaseMiddleware`.
**Fix**: Always use `implements BaseMiddleware<TBody, TUser>` — both type parameters required.
Apply skill 08 + skill 07.

### "Errors from middleware X don't get caught"

**Likely cause**: `ErrorHandlerMiddleware` is positioned after the throwing middleware.
**Fix**: `ErrorHandlerMiddleware` must be first so its `onError` hook (which runs in reverse) fires last.
Apply skill 17 + skill 10.

### "I don't know which error class to use"

Quick reference:
| Situation | Error | Status |
|-----------|-------|--------|
| Bad input | `ValidationError` | 400 |
| Not logged in | `UnauthorizedError` | 401 |
| No permission | `ForbiddenError` | 403 |
| Not found | `NotFoundError` | 404 |
| Duplicate | `ConflictError` | 409 |
| Server broke | `InternalServerError` | 500 |
Apply skill 10.

### "Services resolve to undefined in my middleware"

**Likely cause**: `DependencyInjectionMiddleware` is not in the chain, or is positioned after the middleware that needs services.
**Fix**: Place DI middleware early in the chain (position 2, after ErrorHandler).
Apply skill 11 + skill 17.

### "I want global AND request-scoped services"

**How**: Global services (DB, logger) go in the container pool at startup. Request-scoped data (user, traceId) gets added in middleware to the local scope.
Apply skill 11, then skill 13 for the container pool pattern.

---

## Decision Tree: Which Skill Do I Need?

```
Start here: What are you trying to do?
|
+-- "Build something new"
|   +-- From scratch? --> New Project Journey (apply 01, 05, 06, 17, 10)
|   +-- New endpoint? --> New Endpoint Journey (apply 17, 09, 10)
|   +-- New middleware? --> Apply skill 08
|   +-- Need path params? --> Path Params Journey (apply 04, then 09 or 12)
|
+-- "Fix something broken"
|   +-- Types wrong? --> Apply skill 07, then 08
|   +-- Errors wrong status? --> Apply skill 10
|   +-- Middleware order? --> Apply skill 17
|   +-- Auth not working? --> Apply skill 12, then 17
|   +-- Params undefined? --> Apply skill 04, then 17
|   +-- Services undefined? --> Apply skill 11, then 17
|   +-- Slow cold starts? --> Performance Journey (apply 13, 11)
|
+-- "Add a capability"
|   +-- Authentication? --> Add Auth Journey (apply 12, 17)
|   +-- Validation? --> Apply skill 09
|   +-- Path parameters? --> Apply skill 04
|   +-- DI / services? --> Service Resolution Journey (apply 11, then 13)
|   +-- Local dev? --> Local Dev Journey (apply 01, 02, 06)
|   +-- Custom framework? --> Apply skill 03
|
+-- "Test or optimize"
    +-- Write tests? --> Apply skill 14
    +-- Performance? --> Performance Journey (apply 13, 11)
    +-- Reduce boilerplate? --> Apply skill 07
```
